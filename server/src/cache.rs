// server/src/cache.rs — 优化版 v5
//
// [BUG-05 FIX] is_revoked(): Redis 不可用时仅依赖内存 map，不额外写入（避免误写）
// [BUG-06 FIX] throttle_key() 去掉冗余 lc_ 前缀，统一使用 KEY_NS
// [BUG-11 FIX] set_verify_cache 前检查 activation_ts/expires_at 有效性
// [NEW] mark_revoked_in_memory() 对外暴露，revoke 时主动调用加速拦截
// [OPT-1] set_verify_cache() 增加 activation_ts/expires_at 零值 guard
// [OPT-2] 添加缓存命中率监控
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

// 缓存命中率统计
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

/// 获取缓存命中率统计
pub fn get_cache_stats() -> (u64, u64) {
    let hits = CACHE_HIT_COUNT.load(Ordering::Relaxed);
    let misses = CACHE_MISS_COUNT.load(Ordering::Relaxed);
    (hits, misses)
}

pub fn init_redis_pool(url: &str) -> Result<Pool, deadpool_redis::CreatePoolError> {
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

// [BUG-06 FIX] 去掉多余的 lc_ 前缀，与其他 key 统一使用 KEY_NS
pub fn throttle_key(key_hash: &str) -> String {
    format!("{KEY_NS}throttle:{key_hash}")
}

// ─── 内存 Revoke Fallback（DashMap，线程安全）────────────────────────────────
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

/// 主动写入内存 revoke map（revoke handler 调用）
pub fn mark_revoked_in_memory(key_hash: &str, expires_at: i64) {
    memory_revoke_map().insert(key_hash.to_string(), expires_at);
}

/// 后台 GC：每 5 分钟清理过期 revoke 记录
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

// ─── Verify Cache ────────────────────────────────────────────────────────────

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

/// [OPT-1 + BUG-11] 写入缓存前校验字段有效性
pub async fn set_verify_cache(pool: &RedisPool, key_hash: &str, entry: &VerifyCacheEntry) {
    // 零值 / 逻辑异常 guard
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
    let _: Result<(), _> = conn.del(verify_cache_key(key_hash)).await;
}

// ─── Revoke 检测（三层：内存 → Redis tombstone → false）─────────────────────

/// [BUG-05 FIX]
/// 优先级：内存 map（最快）→ Redis tombstone → false
/// Redis 失败时仅依赖内存（不额外写入，防止不一致）
pub async fn is_revoked(pool: &RedisPool, key_hash: &str) -> bool {
    let mem_map = memory_revoke_map();

    // 1. 内存 map（O(1) 最快路径）
    if let Some(exp) = mem_map.get(key_hash) {
        if *exp > now_ts() {
            return true;
        }
        drop(exp);
        mem_map.remove(key_hash); // 过期条目惰性清理
    }

    // 2. Redis tombstone
    let Ok(mut conn) = pool.get().await else {
        // Redis 不可用：仅依赖内存（步骤 1 已检查），直接返回 false
        return false;
    };

    match conn.get::<_, Option<String>>(tombstone_key(key_hash)).await {
        Ok(Some(_)) => {
            // 同步写入内存 map，加速后续检查
            let exp = now_ts() + tombstone_ttl() as i64;
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
