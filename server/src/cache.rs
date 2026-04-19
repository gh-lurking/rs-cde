// server/src/cache.rs — 优化版 v9
//
// OPT-1 FIX: memory_revoke_map 新增后台 GC（start_cache_cleanup_task）
// OPT-2 FIX: set_verify_cache 增加 activation_ts >= expires_at 校验
// MAJOR-B FIX: tombstone TTL = max(verify_ttl * 100, 86400)
// CRIT-C FIX: set_revoked_tombstone 失败时写内存 fallback
use dashmap::DashMap;
use deadpool_redis::{Config, Pool, PoolConfig, Runtime, Timeouts};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use std::time::Duration;

pub type RedisPool = Pool;

const KEY_NS: &str = "lc:v1:";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VerifyCacheEntry {
    pub key: String,
    pub activation_ts: i64,
    pub expires_at: i64,
}

fn verify_cache_ttl() -> u64 {
    std::env::var("VERIFY_CACHE_TTL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30)
}

/// MAJOR-B FIX: tombstone TTL = max(verify_ttl * 100, 86400)
fn tombstone_ttl() -> u64 {
    let verify_ttl = verify_cache_ttl();
    std::cmp::max(verify_ttl * 100, 86400)
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

fn verify_cache_key(key_hash: &str) -> String {
    format!("{}verify:{}", KEY_NS, key_hash)
}

fn tombstone_key(key_hash: &str) -> String {
    format!("{}revoked:{}", KEY_NS, key_hash)
}

// ── 内存 Revoke Fallback ──────────────────────────────────────────────────────

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

/// OPT-1 FIX: 后台 GC，批量清理过期的内存 revoke 条目
/// 在 main() 中调用此函数启动
pub fn start_cache_cleanup_task() {
    tokio::spawn(cleanup_memory_revokes());
}

async fn cleanup_memory_revokes() {
    loop {
        // 每 5 分钟清理一次（tombstone TTL >= 86400s，5分钟间隔足够）
        tokio::time::sleep(Duration::from_secs(300)).await;
        let map = memory_revoke_map();
        let now = now_ts();
        let before = map.len();
        map.retain(|_, exp| *exp > now);
        let cleaned = before - map.len();
        if cleaned > 0 {
            tracing::info!("[Cache] Cleaned {} expired memory revoke entries", cleaned);
        }
    }
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
            "[Cache] Refusing to cache entry with zero fields for {}...",
            &key_hash[..8.min(key_hash.len())]
        );
        return;
    }

    // OPT-2 FIX: 增加 activation_ts >= expires_at 的完整校验
    if entry.activation_ts >= entry.expires_at {
        tracing::error!(
            "[Cache] Anomalous entry: activation_ts({}) >= expires_at({}) for {}...",
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

// ── Tombstone ─────────────────────────────────────────────────────────────────

/// 检查 key 是否被 revoke（O(1)，检查 Redis tombstone + 内存 fallback）
pub async fn is_revoked(pool: &RedisPool, key_hash: &str) -> bool {
    let mem_map = memory_revoke_map();
    if let Some(exp) = mem_map.get(key_hash) {
        if *exp > now_ts() {
            return true;
        } else {
            drop(exp);
            mem_map.remove(key_hash);
        }
    }
    let Ok(mut conn) = pool.get().await else {
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
        // CRIT-C FIX: Redis 不可用时写内存 fallback
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
            // CRIT-C FIX: Redis 写失败时写内存 fallback
            memory_revoke_map().insert(key_hash.to_string(), revoked_at + ttl as i64);
            tracing::error!(
                "[Cache] Tombstone write FAILED: {}, memory fallback applied. key={}...",
                e,
                &key_hash[..8.min(key_hash.len())]
            );
        }
    }
}
