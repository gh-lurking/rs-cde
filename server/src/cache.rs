// server/src/cache.rs — 优化版
// BUG-B FIX: VerifyCacheEntry 增加 key 字段用于 cache-hit 验签（已正确）
// BUG-NEW-4 FIX: 移除 key 字段——避免原始凭证明文存入 Redis
//   改为 cache-hit 时仍从 DB 取 key 完成验签（cache 仅加速 DB 查询，不缓存凭证）
// VERIFY_CACHE_TTL_SECS 默认从 30 改为 5（减少凭证在内存中的暴露窗口）

use deadpool_redis::{Config, Pool, PoolConfig, Runtime, Timeouts};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub type RedisPool = Pool;

/// /verify 缓存条目
/// BUG-NEW-4 FIX: 移除 key 字段，不再缓存原始凭证
/// cache-hit 时仍需去 DB 获取 key 进行 HMAC 验签
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VerifyCacheEntry {
    // key 字段已移除！不在 Redis 中缓存原始凭证
    pub activation_ts: i64,
    pub expires_at: i64,
    pub revoked: bool,
}

fn verify_cache_ttl() -> u64 {
    std::env::var("VERIFY_CACHE_TTL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5) // BUG-NEW-4 FIX: 默认从 30s 改为 5s，减少凭证暴露窗口
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

/// 从 Redis 读取 /verify 缓存（不含 key 字段）
pub async fn get_verify_cache(pool: &RedisPool, key_hash: &str) -> Option<VerifyCacheEntry> {
    let mut conn = pool.get().await.ok()?;
    let raw: Option<String> = conn.get(cache_key(key_hash)).await.ok()?;
    raw.and_then(|s| serde_json::from_str(&s).ok())
}

/// 将 /verify 结果写入 Redis（不含 key 字段）
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

/// 主动失效某个 key_hash 的 /verify 缓存（DEL）
pub async fn invalidate_verify_cache(pool: &RedisPool, key_hash: &str) {
    let Ok(mut conn) = pool.get().await else {
        return;
    };
    let _: Result<(), _> = conn.del(cache_key(key_hash)).await;
    tracing::debug!(
        "Invalidated Redis Cache: verify:{}",
        &key_hash[..8.min(key_hash.len())]
    );
}
