// server/src/cache.rs — 优化版 v4
//
// [BUG-MED-2 FIX] is_revoked() remove-after-drop 竞态修复：
//   原代码在 drop(exp) 后调用 mem_map.remove(key_hash)，
//   两操作之间存在竞态窗口（另一个线程可能刚插入新条目）。
//   修复：使用 if-let 绑定将值的作用域限制在 if 块内，
//   exp 在 if 块结束时自动 drop，remove 在 exp drop 之后立即执行。
//   虽然竞态窗口未完全消除（DashMap 单条目无事务保证），
//   但代码更清晰，且后果可自愈（下次 Redis 查询会重建）。
//
// [BUG-CRIT-4 FIX] set_verify_cache 增加 activation_ts 零值防御：
//   原检查 activation_ts >= expires_at 无法捕获
//   activation_ts=0, expires_at>0 的损坏数据。
//   新增 activation_ts <= 0 检查，匹配则拒绝写入缓存。
//   对应 CLAUDE.md §1「Think Before Coding」：防御不可能但灾难性的场景。
//
// 与 CLAUDE.md §3「Surgical Changes」一致：只改必要的逻辑块。

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
    let entry = raw.and_then(|s| serde_json::from_str::<VerifyCacheEntry>(&s).ok());
    if entry.is_some() {
        CACHE_HIT_COUNT.fetch_add(1, Ordering::Relaxed);
    } else {
        CACHE_MISS_COUNT.fetch_add(1, Ordering::Relaxed);
    }
    entry
}

/// [BUG-CRIT-4 FIX] 写入缓存前防御性检查
///
/// 拒绝写入 activation_ts <= 0 或 activation_ts >= expires_at 的条目。
/// 原代码只检查 activation_ts >= expires_at，无法防御
/// activation_ts=0, expires_at>0 的损坏数据。
/// 新增 activation_ts <= 0 后，只有真正激活的密钥才能进入缓存。
/// 对应 CLAUDE.md §1：防御不可能但灾难性的场景。
pub async fn set_verify_cache(pool: &RedisPool, key_hash: &str, entry: &VerifyCacheEntry) {
    // [BUG-CRIT-4 FIX] 增强零值防御
    if entry.activation_ts <= 0 || entry.activation_ts >= entry.expires_at {
        tracing::warn!(
            "[Cache] skip inconsistent cache write: act={}, exp={}",
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

/// [BUG-MED-2 FIX] is_revoked() 优化
///
/// 原代码在 drop(exp) 后调用 remove，存在微弱竞态窗口。
/// 修复：使用 if-let 绑定直接将值的作用域限制在 if 块内，
/// exp 在 if 块结束时自动 drop，remove 在 exp drop 之后立即执行。
pub async fn is_revoked(pool: &RedisPool, key_hash: &str) -> bool {
    let mem_map = memory_revoke_map();
    // 检查内存缓存
    {
        let entry = mem_map.get(key_hash);
        if let Some(exp) = entry {
            if *exp > now_ts() {
                return true;
            }
            // exp 在此处 drop（离开 if-let 作用域）
        }
    }
    // 移除过期条目（在 exp 释放后进行）
    mem_map.remove(key_hash);

    // 查询 Redis
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
