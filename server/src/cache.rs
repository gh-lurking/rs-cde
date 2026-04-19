// server/src/cache.rs — 优化版 v7
//
// ✅ OPT-2 FIX: tombstone 分离到独立命名空间
//   verify:{key_hash}  → 正常缓存 (VerifyCacheEntry, 无 revoked 字段)
//   revoked:{key_hash} → tombstone (仅存撤销时间戳)
//   消除原有 key=""、revoked=true 等魔法值设计
// ✅ 保留原有: MAJOR-3 tombstone TTL >= 1h

use deadpool_redis::{Config, Pool, PoolConfig, Runtime, Timeouts};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub type RedisPool = Pool;

/// 正常缓存条目（不含 revoked 字段，tombstone 通过命名空间区分）
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VerifyCacheEntry {
    pub key: String, // 明文 License key，用于 cache hit 时 HMAC 验签（BUG-1 修复依赖）
    pub activation_ts: i64, // 必须 > 0
    pub expires_at: i64, // 必须 > activation_ts
                     // revoked 字段已移除：通过 is_revoked() 检查独立命名空间
}

fn verify_cache_ttl() -> u64 {
    std::env::var("VERIFY_CACHE_TTL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30)
}

/// tombstone TTL = max(verify_cache_ttl()*10, 3600)，至少 1 小时
fn tombstone_ttl() -> u64 {
    std::cmp::max(verify_cache_ttl() * 10, 3600)
}

pub fn init_redis_pool(redis_url: &str) -> Result<Pool, deadpool_redis::CreatePoolError> {
    let max_size: usize = std::env::var("REDIS_POOL_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(32);
    let cfg = Config {
        url: Some(redis_url.to_string()),
        pool: Some(PoolConfig {
            max_size,
            timeouts: Timeouts {
                wait: Some(Duration::from_secs(3)),
                create: Some(Duration::from_secs(5)),
                recycle: Some(Duration::from_secs(2)),
            },
            ..Default::default()
        }),
        ..Default::default()
    };
    cfg.create_pool(Some(Runtime::Tokio1))
}

// ── Redis Key 命名空间（分离 tombstone）──────────────────────────────────────
fn verify_cache_key(key_hash: &str) -> String {
    format!("verify:{}", key_hash)
}

fn tombstone_key(key_hash: &str) -> String {
    format!("revoked:{}", key_hash) // ✅ OPT-2: 独立命名空间
}

// ── 正常缓存操作 ──────────────────────────────────────────────────────────────
pub async fn get_verify_cache(pool: &RedisPool, key_hash: &str) -> Option<VerifyCacheEntry> {
    let mut conn = pool.get().await.ok()?;
    let raw: Option<String> = conn.get(verify_cache_key(key_hash)).await.ok()?;
    raw.and_then(|s| serde_json::from_str(&s).ok())
}

pub async fn set_verify_cache(pool: &RedisPool, key_hash: &str, entry: &VerifyCacheEntry) {
    // 防御：不缓存 activation_ts/expires_at 无效的脏数据
    if entry.activation_ts <= 0 || entry.expires_at <= 0 {
        tracing::warn!(
            "[Cache] Refused to cache invalid entry (activation_ts={}, expires_at={}) for key_hash={}...",
            entry.activation_ts,
            entry.expires_at,
            &key_hash[..8.min(key_hash.len())]
        );
        return;
    }
    let Ok(json) = serde_json::to_string(entry) else {
        return;
    };
    let Ok(mut conn) = pool.get().await else {
        return;
    };
    let _: Result<Option<String>, _> = redis::cmd("SET")
        .arg(verify_cache_key(key_hash))
        .arg(&json)
        .arg("EX")
        .arg(verify_cache_ttl())
        .query_async(&mut conn)
        .await;
}

// ── Tombstone 操作（独立命名空间）────────────────────────────────────────────

/// 检查 key 是否已撤销（O(1)，通过独立 Redis key 前缀）
pub async fn is_revoked(pool: &RedisPool, key_hash: &str) -> bool {
    let Ok(mut conn) = pool.get().await else {
        // Redis 不可用时保守策略：不声称已撤销（允许 DB 回源判断）
        return false;
    };
    let exists: bool = conn.exists(tombstone_key(key_hash)).await.unwrap_or(false);
    exists
}

/// 写入 revoke tombstone（至少保留 1 小时）
pub async fn set_revoked_tombstone(pool: &RedisPool, key_hash: &str) {
    let Ok(mut conn) = pool.get().await else {
        tracing::error!(
            "[Cache] Redis unavailable, tombstone write FAILED! Revoke may be delayed. key_hash={}...",
            &key_hash[..8.min(key_hash.len())]
        );
        return;
    };
    let revoked_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let result: Result<String, _> = redis::cmd("SET")
        .arg(tombstone_key(key_hash))
        .arg(revoked_at.to_string()) // 存储撤销时间戳（用于审计）
        .arg("EX")
        .arg(tombstone_ttl())
        .query_async(&mut conn)
        .await;
    match result {
        Ok(_) => tracing::info!(
            "[Cache] Tombstone written, TTL={}s, key_hash={}...",
            tombstone_ttl(),
            &key_hash[..8.min(key_hash.len())]
        ),
        Err(e) => tracing::error!(
            "[Cache] Tombstone write FAILED: {}, revoke may be delayed! key_hash={}...",
            e,
            &key_hash[..8.min(key_hash.len())]
        ),
    }
}

/// 删除正常缓存（不影响 tombstone）
pub async fn invalidate_verify_cache(pool: &RedisPool, key_hash: &str) {
    let Ok(mut conn) = pool.get().await else {
        return;
    };
    let _: Result<i64, _> = conn.del(verify_cache_key(key_hash)).await;
    tracing::debug!(
        "Invalidated Redis cache: verify:{}...",
        &key_hash[..8.min(key_hash.len())]
    );
}
