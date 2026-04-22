// server/src/cache.rs — 优化版 v6
//
// [BUG-05 FIX]  is_revoked(): Redis 不可用时仅依赖内存 map，不额外写入
// [BUG-06 FIX]  throttle_key() 去掉冗余前缀，统一使用 KEY_NS
// [BUG-11 FIX]  set_verify_cache 前检查 activation_ts/expires_at 有效性
// [BUG-S7 FIX]  tombstone TTL 查询异常时使用保守值（tombstone_ttl()）而非 0
// [OPT-1]       缓存写入增加零值 guard
// [OPT-2]       缓存命中率监控

use dashmap::DashMap;
use deadpool_redis::{Config, Pool, PoolConfig, Runtime, Timeouts};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
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

static VERIFY_CACHE_TTL: OnceLock<u64> = OnceLock::new();
static TOMBSTONE_TTL: OnceLock<u64> = OnceLock::new();

static CACHE_HIT_COUNT: AtomicU64 = AtomicU64::new(0);
static CACHE_MISS_COUNT: AtomicU64 = AtomicU64::new(0);

fn verify_cache_ttl() -> u64 {
    *VERIFY_CACHE_TTL.get_or_init(|| {
        std::env::var("VERIFY_CACHE_TTL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30)
    })
}

fn tombstone_ttl() -> u64 {
    *TOMBSTONE_TTL.get_or_init(|| std::cmp::max(verify_cache_ttl() * 100, 86400))
}

pub fn get_cache_stats() -> (u64, u64) {
    (
        CACHE_HIT_COUNT.load(Ordering::Relaxed),
        CACHE_MISS_COUNT.load(Ordering::Relaxed),
    )
}

pub fn init_redis_pool(url: &str) -> Result<RedisPool, deadpool_redis::CreatePoolError> {
    let max_size: usize = std::env::var("REDIS_POOL_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(32);

    let cfg = Config {
        url: Some(url.to_string()),
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
    Ok(cfg.create_pool(Some(Runtime::Tokio1))?)
}

fn verify_cache_key(key_hash: &str) -> String {
    format!("{KEY_NS}verify:{key_hash}")
}

fn tombstone_key(key_hash: &str) -> String {
    format!("{KEY_NS}revoked:{key_hash}")
}

pub fn throttle_key(key_hash: &str) -> String {
    format!("{KEY_NS}throttle:{key_hash}")
}

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

pub fn mark_revoked_in_memory(key_hash: &str, expires_at: i64) {
    memory_revoke_map().insert(key_hash.to_string(), expires_at);
}

pub fn start_cache_cleanup_task() {
    tokio::spawn(cleanup_memory_revokes());
}

async fn cleanup_memory_revokes() {
    loop {
        tokio::time::sleep(Duration::from_secs(300)).await;
        let map = memory_revoke_map();
        let now = now_ts();
        let before = map.len();
        map.retain(|_, exp| *exp > now);
        let cleaned = before - map.len();
        if cleaned > 0 {
            tracing::info!("[Cache] 清理 {} 条过期 revoke 记录", cleaned);
        }
    }
}

pub async fn get_verify_cache(pool: &RedisPool, key_hash: &str) -> Option<VerifyCacheEntry> {
    let mut conn = pool.get().await.ok()?;
    let raw: Option<String> = conn.get(verify_cache_key(key_hash)).await.ok()?;
    let entry = raw.and_then(|s| serde_json::from_str(&s).ok());
    if entry.is_some() {
        CACHE_HIT_COUNT.fetch_add(1, Ordering::Relaxed);
    } else {
        CACHE_MISS_COUNT.fetch_add(1, Ordering::Relaxed);
    }
    entry
}

// [OPT-1 + BUG-11 FIX] 写入缓存前校验字段有效性
pub async fn set_verify_cache(pool: &RedisPool, key_hash: &str, entry: &VerifyCacheEntry) {
    if entry.activation_ts == 0 || entry.expires_at == 0 {
        tracing::warn!("[Cache] 跳过零值缓存写入: {}", key_hash);
        return;
    }
    if entry.activation_ts >= entry.expires_at {
        tracing::warn!(
            "[Cache] 跳过逻辑异常缓存: act={} >= exp={}",
            entry.activation_ts,
            entry.expires_at
        );
        return;
    }

    let Ok(json) = serde_json::to_string(entry) else {
        tracing::warn!("[Cache] JSON 序列化失败");
        return;
    };
    let Ok(mut conn) = pool.get().await else {
        return;
    };
    let _: Result<(), _> = redis::cmd("SET")
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

// [BUG-05 FIX] 优先级：内存 map → Redis tombstone → false
// [BUG-S7 FIX] TTL 查询异常时使用 tombstone_ttl() 作为保守值
pub async fn is_revoked(pool: &RedisPool, key_hash: &str) -> bool {
    let mem_map = memory_revoke_map();

    // 1. 内存 map（O(1) 最快路径）
    if let Some(exp) = mem_map.get(key_hash) {
        if *exp > now_ts() {
            return true;
        }
        drop(exp);
        mem_map.remove(key_hash);
    }

    // 2. Redis tombstone
    let Ok(mut conn) = pool.get().await else {
        return false;
    };

    match conn.get::<_, Option<String>>(tombstone_key(key_hash)).await {
        Ok(Some(_)) => {
            // [BUG-S7 FIX] TTL 查询失败时使用完整 tombstone_ttl() 而非 0
            let remaining_ttl: i64 = redis::cmd("TTL")
                .arg(tombstone_key(key_hash))
                .query_async(&mut conn)
                .await
                .unwrap_or(tombstone_ttl() as i64);

            let exp = now_ts() + remaining_ttl.max(tombstone_ttl() as i64 / 2);
            mem_map.insert(key_hash.to_string(), exp);
            true
        }
        Ok(None) => false,
        Err(e) => {
            tracing::warn!("[Cache] tombstone 查询失败: {}", e);
            false
        }
    }
}

pub async fn set_revoke_tombstone(pool: &RedisPool, key_hash: &str) {
    let Ok(mut conn) = pool.get().await else {
        return;
    };
    let _: Result<(), _> = redis::cmd("SET")
        .arg(tombstone_key(key_hash))
        .arg("1")
        .arg("EX")
        .arg(tombstone_ttl())
        .query_async(&mut conn)
        .await;
}
