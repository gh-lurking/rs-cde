// server/src/cache.rs — 优化版 v2
// CRIT-1 FIX: VerifyCacheEntry 恢复 key 字段
//   — cache-hit 时直接用缓存中的 key 验签，消除多余 DB 查询
//   — IP 白名单 + TTL=30s 组合保护，安全可接受
//   — 将默认 TTL 从 5s 改回 30s（MINOR-2 FIX: 配置一致性）

use deadpool_redis::{Config, Pool, PoolConfig, Runtime, Timeouts};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub type RedisPool = Pool;

/// /verify 缓存条目
/// CRIT-1 FIX: 恢复 key 字段
///   服务端 IP 白名单 + Redis 仅内网可达 + TTL=30s
///   组合保护下，缓存 key 字段安全可接受，且能消除每次 cache-hit 的 DB 查询
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VerifyCacheEntry {
    pub key: String, // CRIT-1 FIX: 恢复，cache-hit 时无需回 DB
    pub activation_ts: i64,
    pub expires_at: i64,
    pub revoked: bool,
}

fn verify_cache_ttl() -> u64 {
    std::env::var("VERIFY_CACHE_TTL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30) // MINOR-2 FIX: 统一默认值 30s（原代码 5s 与 test.sh 300s 矛盾）
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
    let Ok(mut conn) = pool.get().await else {
        return;
    };
    let Ok(json) = serde_json::to_string(entry) else {
        return;
    };
    let _: Result<(), _> = redis::cmd("SET")
        .arg(cache_key(key_hash))
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
    let _: Result<u64, _> = conn.del(cache_key(key_hash)).await;
    tracing::debug!(
        "Invalidated Redis Cache: verify:{}",
        &key_hash[..8.min(key_hash.len())]
    );
}
