// server/src/cache.rs — 优化版 v3
//
// ✅ OPT-CRIT-1/2: 新增 set_revoked_tombstone，吊销时写入 revoked=true 条目
//                  而非单纯 DEL，确保 Redis 故障时吊销依然即时生效
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

// ✅ OPT-CRIT-1/2: 写入 tombstone（revoked=true 条目），而非单纯 DEL
// 这样即便并发请求在 DEL 后 SET 之间缝隙命中 cache，
// 也不会取到旧的 revoked=false 条目（tombstone 直接拒绝）
pub async fn set_revoked_tombstone(pool: &RedisPool, key_hash: &str) {
    // tombstone 中的 key 字段不需要真实值（handler 中 revoked=true 会直接拒绝，
    // 不会走到 verify_hmac_signature），设为空字符串节省内存
    let tombstone = VerifyCacheEntry {
        key: String::new(), // tombstone 不需要真实 key
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
    // TTL = verify_cache_ttl，过期后自动清理（不影响后续正常缓存）
    let result: Result<(), _> = redis::cmd("SET")
        .arg(cache_key(key_hash))
        .arg(&json)
        .arg("EX")
        .arg(verify_cache_ttl())
        .query_async(&mut conn)
        .await;
    if let Err(e) = result {
        tracing::error!("[Cache] tombstone 写入失败: {}，吊销可能延迟生效", e);
    }
}

pub async fn invalidate_verify_cache(pool: &RedisPool, key_hash: &str) {
    let Ok(mut conn) = pool.get().await else {
        return;
    };
    let _: Result<i64, _> = conn.del(cache_key(key_hash)).await;
    tracing::debug!(
        "Invalidated Redis Cache: verify:{}",
        &key_hash[..8.min(key_hash.len())]
    );
}
