// server/src/cache.rs — 优化版 v4 (Bug修复版)
//
// ✅ MAJOR-3 FIX: tombstone 使用 tombstone_ttl()（max(verify_cache_ttl*10, 3600)）
//   确保吊销 tombstone 存活足够长，覆盖所有客户端轮询周期
use deadpool_redis::{Config, Pool, PoolConfig, Runtime, Timeouts};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub type RedisPool = Pool;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VerifyCacheEntry {
    pub key: String,
    pub activation_ts: i64,
    pub expires_at: i64,
    pub revoked: bool,
}

fn verify_cache_ttl() -> u64 {
    std::env::var("VERIFY_CACHE_TTL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30)
}

/// ✅ MAJOR-3 FIX: tombstone TTL 独立于普通缓存 TTL
/// 使用更长的 TTL 确保吊销能覆盖所有客户端的轮询周期
/// 最小 1 小时，或普通 TTL 的 10 倍（取较大值）
fn tombstone_ttl() -> u64 {
    let base = verify_cache_ttl();
    std::cmp::max(base * 10, 3600)
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

fn cache_key(key_hash: &str) -> String {
    format!("verify:{}", key_hash)
}

pub async fn get_verify_cache(pool: &RedisPool, key_hash: &str) -> Option<VerifyCacheEntry> {
    let mut conn = pool.get().await.ok()?;
    let raw: Option<String> = conn.get(cache_key(key_hash)).await.ok()?;
    raw.and_then(|s| serde_json::from_str(&s).ok())
}

pub async fn set_verify_cache(pool: &RedisPool, key_hash: &str, entry: &VerifyCacheEntry) {
    let Ok(mut conn) = pool.get().await else {
        return;
    };
    let Ok(json) = serde_json::to_string(entry) else {
        return;
    };
    let _: Result<String, _> = redis::cmd("SET")
        .arg(cache_key(key_hash))
        .arg(&json)
        .arg("EX")
        .arg(verify_cache_ttl())
        .query_async(&mut conn)
        .await;
}

/// ✅ MAJOR-3 FIX: 使用 tombstone_ttl() 而非 verify_cache_ttl()
/// tombstone 需要比普通缓存活得更久，确保吊销状态可靠传播
pub async fn set_revoked_tombstone(pool: &RedisPool, key_hash: &str) {
    let tombstone = VerifyCacheEntry {
        key: String::new(), // tombstone 不需要真实 key（已在 handler 中 revoked 优先判断）
        activation_ts: 0,
        expires_at: 0,
        revoked: true,
    };
    let Ok(mut conn) = pool.get().await else {
        tracing::error!("[Cache] Redis 不可用，tombstone 写入失败！吊销可能延迟生效");
        return;
    };
    let Ok(json) = serde_json::to_string(&tombstone) else {
        return;
    };
    // ✅ MAJOR-3 FIX: 使用 tombstone_ttl()（min 1h，保证覆盖客户端轮询周期）
    let result: Result<String, _> = redis::cmd("SET")
        .arg(cache_key(key_hash))
        .arg(&json)
        .arg("EX")
        .arg(tombstone_ttl()) // ← 修复点
        .query_async(&mut conn)
        .await;
    if let Err(e) = result {
        tracing::error!("[Cache] tombstone 写入失败: {}，吊销可能延迟生效", e);
    } else {
        tracing::info!(
            "[Cache] tombstone 写入成功，TTL={}s，key_hash={}...",
            tombstone_ttl(),
            &key_hash[..8.min(key_hash.len())]
        );
    }
}

pub async fn invalidate_verify_cache(pool: &RedisPool, key_hash: &str) {
    let Ok(mut conn) = pool.get().await else {
        return;
    };
    let _: Result<u64, _> = conn.del(cache_key(key_hash)).await;
    tracing::debug!(
        "Invalidated Redis Cache: verify:{}",
        &key_hash[..8.min(key_hash.len())]
    );
}
