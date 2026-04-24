// server/src/cache.rs — 优化版 v2
//
// [BUG-H1 FIX] is_revoked() 热路径：tombstone_key 局部变量复用，消除重复String分配
// [BUG-C1 FIX] tombstone TTL 查询失败时降级为 MIN_MEMORY_REVOKE_TTL（60s）

use dashmap::DashMap;
use deadpool_redis::{Config, Pool, PoolConfig, Runtime, Timeouts};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};

use std::sync::atomic::Ordering::SeqCst;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

pub type RedisPool = Pool;

const KEY_NS: &str = "lc:v1:";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VerifyCacheEntry {
    pub activation_ts: i64,
    pub expires_at: i64,
}

static VERIFY_CACHE_TTL: OnceLock<u64> = OnceLock::new();
static TOMBSTONE_TTL: OnceLock<u64> = OnceLock::new();
static CACHE_HIT_COUNT: AtomicU64 = AtomicU64::new(0);
static CACHE_MISS_COUNT: AtomicU64 = AtomicU64::new(0);
static CACHE_CLEANUP_STARTED: AtomicBool = AtomicBool::new(false);

const MIN_MEMORY_REVOKE_TTL: i64 = 60;

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
    if CACHE_CLEANUP_STARTED
        .compare_exchange(false, true, SeqCst, SeqCst)
        .is_err()
    {
        return;
    }
    tokio::spawn(async {
        loop {
            cleanup_memory_revokes_once().await;
            tokio::time::sleep(Duration::from_secs(300)).await;
        }
    });
}

async fn cleanup_memory_revokes_once() {
    let map = memory_revoke_map();
    let now = now_ts();
    let before = map.len();
    map.retain(|_, exp| *exp > now);
    let cleaned = before - map.len();
    if cleaned > 0 {
        tracing::info!("[Cache] GC cleaned {} expired revoke records", cleaned);
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

pub async fn set_verify_cache(pool: &RedisPool, key_hash: &str, entry: &VerifyCacheEntry) {
    if entry.activation_ts <= 0 || entry.expires_at <= 0 {
        tracing::warn!("[Cache] skip invalid cache write: {}", key_hash);
        return;
    }
    if entry.activation_ts >= entry.expires_at {
        tracing::warn!(
            "[Cache] skip inconsistent cache write: act={} >= exp={}",
            entry.activation_ts,
            entry.expires_at
        );
        return;
    }

    let Ok(json) = serde_json::to_string(entry) else {
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
    let _: Result<(), _> = conn.del(verify_cache_key(key_hash)).await;
}

pub async fn is_revoked(pool: &RedisPool, key_hash: &str) -> bool {
    let mem_map = memory_revoke_map();
    if let Some(exp) = mem_map.get(key_hash) {
        if *exp > now_ts() {
            return true;
        }
        drop(exp);
        mem_map.remove(key_hash);
    }

    let Ok(mut conn) = pool.get().await else {
        return false;
    };
    let tkey = tombstone_key(key_hash);

    match conn.get::<_, Option<String>>(&tkey).await {
        Ok(Some(_)) => {
            let remaining_ttl: i64 = redis::cmd("TTL")
                .arg(&tkey)
                .query_async(&mut conn)
                .await
                .unwrap_or(MIN_MEMORY_REVOKE_TTL);
            let effective_ttl = remaining_ttl
                .max(MIN_MEMORY_REVOKE_TTL)
                .min(tombstone_ttl() as i64);
            let exp = now_ts() + effective_ttl;
            mem_map.insert(key_hash.to_string(), exp);
            true
        }
        Ok(None) => false,
        Err(e) => {
            tracing::warn!("[Cache] tombstone read failed: {}", e);
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
