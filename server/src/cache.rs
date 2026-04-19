// server/src/cache.rs — 优化版 v6
// ✅ MAJOR-3 (原有): tombstone 使用 tombstone_ttl()（min 1h）
// ✅ 新增: set_verify_cache 防御增强：activation_ts/expires_at 必须 > 0

use deadpool_redis::{Config, Pool, PoolConfig, Runtime, Timeouts};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub type RedisPool = Pool;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VerifyCacheEntry {
    pub key: String, // tombstone 时为空串 ""
    pub activation_ts: i64,
    pub expires_at: i64,
    pub revoked: bool, // true = tombstone
}

fn verify_cache_ttl() -> u64 {
    std::env::var("VERIFY_CACHE_TTL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30)
}

/// tombstone TTL = max(verify_cache_ttl()*10, 3600)，至少 1 小时
fn tombstone_ttl() -> u64 {
    let base = verify_cache_ttl();
    std::cmp::max(base * 10, 3600)
}

pub fn init_redis_pool(redis_url: &str) -> Result<RedisPool, deadpool_redis::CreatePoolError> {
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
    // 防御：不缓存 revoked / 未激活 / expires_at=0 的脏数据
    if entry.revoked || entry.activation_ts <= 0 || entry.expires_at <= 0 {
        tracing::warn!(
            "[Cache] Skipped caching invalid entry for key_hash={}...",
            &key_hash[..8.min(key_hash.len())]
        );
        return;
    }

    let Ok(mut conn) = pool.get().await else {
        return;
    };

    let Ok(json) = serde_json::to_string(entry) else {
        return;
    };

    let _: Result<Option<String>, _> = redis::cmd("SET")
        .arg(cache_key(key_hash))
        .arg(&json)
        .arg("EX")
        .arg(verify_cache_ttl())
        .query_async(&mut conn)
        .await;
}

/// tombstone: revoked=true, key="", activation_ts=0, expires_at=0
/// TTL 至少 1 小时，保证 revoke 后足够长时间内拒绝访问
pub async fn set_revoked_tombstone(pool: &RedisPool, key_hash: &str) {
    let tombstone = VerifyCacheEntry {
        key: String::new(),
        activation_ts: 0,
        expires_at: 0,
        revoked: true,
    };

    let Ok(mut conn) = pool.get().await else {
        tracing::error!(
            "[Cache] Redis unavailable, tombstone write failed! Revoke may be delayed. key_hash={}...",
            &key_hash[..8.min(key_hash.len())]
        );
        return;
    };

    let Ok(json) = serde_json::to_string(&tombstone) else {
        return;
    };

    let result: Result<String, _> = redis::cmd("SET")
        .arg(cache_key(key_hash))
        .arg(&json)
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
            "[Cache] Tombstone write failed: {}, revoke may be delayed! key_hash={}...",
            e,
            &key_hash[..8.min(key_hash.len())]
        ),
    }
}

pub async fn invalidate_verify_cache(pool: &RedisPool, key_hash: &str) {
    let Ok(mut conn) = pool.get().await else {
        return;
    };

    let _: Result<i64, _> = conn.del(cache_key(key_hash)).await;
    tracing::debug!(
        "Invalidated Redis cache: verify:{}...",
        &key_hash[..8.min(key_hash.len())]
    );
}
