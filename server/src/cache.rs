// server/src/cache.rs — 优化版 v8
//
// ✅ OPT-2 FIX: tombstone key 前缀改为 "revoked:{key_hash}"（已是最新）
// ✅ MAJOR-B FIX: tombstone TTL = max(verify_ttl * 100, 86400)
// ✅ CRIT-C FIX: set_revoked_tombstone 失败时写内存 fallback
// ✅ MAJOR-3 FIX: tombstone TTL >= 1h (已是最新)

use dashmap::DashMap;
use deadpool_redis::{Config, Pool, PoolConfig, Runtime, Timeouts};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use std::time::Duration;

pub type RedisPool = Pool;

/// 命名空间前缀，防止多服务 Redis key 冲突
const KEY_NS: &str = "lc:v1:";

/// verify cache entry（不含 revoked，tombstone 单独存储）
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VerifyCacheEntry {
    pub key: String,        // 原始 License Key，用于 cache hit 时 HMAC 验证
    pub activation_ts: i64, // 必须 > 0
    pub expires_at: i64,    // 必须 > activation_ts
}

fn verify_cache_ttl() -> u64 {
    std::env::var("VERIFY_CACHE_TTL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30)
}

/// ✅ MAJOR-B FIX: tombstone TTL 固定下限
/// = max(verify_ttl * 100, 86400)，确保 tombstone 永远比 cache 存活时间长
fn tombstone_ttl() -> u64 {
    let verify_ttl = verify_cache_ttl();
    std::cmp::max(verify_ttl * 100, 86400)
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

// ── Redis Key 生成 ────────────────────────────────────────────────────────────
/// ✅ OPT-2 FIX: 版本化命名空间
fn verify_cache_key(key_hash: &str) -> String {
    format!("{}verify:{}", KEY_NS, key_hash)
}

fn tombstone_key(key_hash: &str) -> String {
    format!("{}revoked:{}", KEY_NS, key_hash)
}

// ── 内存 Revoke Fallback ──────────────────────────────────────────────────────
/// ✅ CRIT-C FIX: Redis tombstone 写失败时的内存黑名单 fallback
static MEMORY_REVOKE_FALLBACK: OnceLock<DashMap<String, i64>> = OnceLock::new();

fn memory_revoke_map() -> &'static DashMap<String, i64> {
    MEMORY_REVOKE_FALLBACK.get_or_init(DashMap::new)
}

fn now_ts() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

// ── Verify Cache ──────────────────────────────────────────────────────────────
pub async fn get_verify_cache(pool: &RedisPool, key_hash: &str) -> Option<VerifyCacheEntry> {
    let mut conn = pool.get().await.ok()?;
    let raw: Option<String> = conn.get(verify_cache_key(key_hash)).await.ok()?;
    raw.and_then(|s| serde_json::from_str(&s).ok())
}

pub async fn set_verify_cache(pool: &RedisPool, key_hash: &str, entry: &VerifyCacheEntry) {
    // 拒绝缓存无效 entry
    if entry.activation_ts <= 0 || entry.expires_at <= 0 {
        tracing::warn!(
            "[Cache] Refused to cache invalid entry (act={}, exp={}) for {}...",
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

pub async fn invalidate_verify_cache(pool: &RedisPool, key_hash: &str) {
    let Ok(mut conn) = pool.get().await else {
        return;
    };
    let _: Result<i64, _> = conn.del(verify_cache_key(key_hash)).await;
}

// ── Tombstone ──────────────────────────────────────────────────────────────────
/// 检查 key 是否被 revoke（O(1)，检查 Redis tombstone + 内存 fallback）
pub async fn is_revoked(pool: &RedisPool, key_hash: &str) -> bool {
    // 先检查内存 fallback
    let mem_map = memory_revoke_map();
    if let Some(exp) = mem_map.get(key_hash) {
        if *exp > now_ts() {
            return true;
        } else {
            drop(exp);
            mem_map.remove(key_hash);
        }
    }

    // 再检查 Redis
    let Ok(mut conn) = pool.get().await else {
        // Redis 不可用，降级：不阻断（已有内存 fallback 覆盖近期 revoke）
        return false;
    };
    let exists: bool = conn.exists(tombstone_key(key_hash)).await.unwrap_or(false);
    exists
}

/// 写入 revoke tombstone（TTL >= 24h）
pub async fn set_revoked_tombstone(pool: &RedisPool, key_hash: &str) {
    let revoked_at = now_ts();
    let ttl = tombstone_ttl();

    let Ok(mut conn) = pool.get().await else {
        // ✅ CRIT-C FIX: Redis 不可用时写内存 fallback
        memory_revoke_map().insert(key_hash.to_string(), revoked_at + ttl as i64);
        tracing::error!(
            "[Cache] Redis unavailable, tombstone FAILED! Using memory fallback. key={}...",
            &key_hash[..8.min(key_hash.len())]
        );
        return;
    };

    let result: Result<String, _> = redis::cmd("SET")
        .arg(tombstone_key(key_hash))
        .arg(revoked_at.to_string())
        .arg("EX")
        .arg(ttl)
        .query_async(&mut conn)
        .await;

    match result {
        Ok(_) => tracing::info!(
            "[Cache] Tombstone written, TTL={}s, key={}...",
            ttl,
            &key_hash[..8.min(key_hash.len())]
        ),
        Err(e) => {
            // ✅ CRIT-C FIX: Redis 写失败时写内存 fallback
            memory_revoke_map().insert(key_hash.to_string(), revoked_at + ttl as i64);
            tracing::error!(
                "[Cache] Tombstone write FAILED: {}, memory fallback applied. key={}...",
                e,
                &key_hash[..8.min(key_hash.len())]
            );
        }
    }
}
