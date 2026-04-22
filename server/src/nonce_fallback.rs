// server/src/nonce_fallback.rs — 优化版 v4
//
// [BUG-02 FIX] check_and_store 语义完全修正
// [BUG-13 FIX] 增加 nonce 计数指标，便于监控 DoS 攻击
// [OPT] Entry API 原子化 check+insert，消除 TOCTOU 竞态
// [OPT] MAX_NONCE_ENTRIES 上界防内存耗尽 DoS

use dashmap::DashMap;
use once_cell::sync::Lazy;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::time::{SystemTime, UNIX_EPOCH};

struct NonceEntry {
    expires_at: u64,
}

const MAX_NONCE_ENTRIES: usize = 500_000;

static MEMORY_NONCES: Lazy<Arc<DashMap<String, NonceEntry>>> =
    Lazy::new(|| Arc::new(DashMap::new()));

static CLEANUP_STARTED: AtomicBool = AtomicBool::new(false);
static NONCE_CHECKED_COUNT: AtomicUsize = AtomicUsize::new(0);
static NONCE_REJECTED_COUNT: AtomicUsize = AtomicUsize::new(0);

fn nonce_map() -> &'static Arc<DashMap<String, NonceEntry>> {
    &MEMORY_NONCES
}

pub fn get_nonce_stats() -> (usize, usize, usize) {
    let total = NONCE_CHECKED_COUNT.load(Ordering::Relaxed);
    let rejected = NONCE_REJECTED_COUNT.load(Ordering::Relaxed);
    let map_size = nonce_map().len();
    (total, rejected, map_size)
}

pub fn reset_nonce_stats() {
    NONCE_CHECKED_COUNT.store(0, Ordering::Relaxed);
    NONCE_REJECTED_COUNT.store(0, Ordering::Relaxed);
}

pub fn start_cleanup_task() {
    if CLEANUP_STARTED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        tokio::spawn(cleanup_loop());
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Nonce 去重（Redis 不可用时的内存降级）
///
/// 返回 true  -> nonce 首次出现（或已过期），请求合法
/// 返回 false -> nonce 在有效期内，重放攻击，拒绝
pub fn check_and_store(key: &str, ttl_secs: u64) -> bool {
    let map = nonce_map();
    let now = now_secs();
    let expires_at = now + ttl_secs;

    NONCE_CHECKED_COUNT.fetch_add(1, Ordering::Relaxed);

    if map.len() >= MAX_NONCE_ENTRIES {
        tracing::error!(
            "[NonceFallback] 内存已满 ({}), 拒绝新 nonce",
            MAX_NONCE_ENTRIES
        );
        NONCE_REJECTED_COUNT.fetch_add(1, Ordering::Relaxed);
        return false;
    }

    use dashmap::mapref::entry::Entry;
    match map.entry(key.to_string()) {
        Entry::Occupied(mut e) => {
            if e.get().expires_at > now {
                NONCE_REJECTED_COUNT.fetch_add(1, Ordering::Relaxed);
                return false;
            }
            e.insert(NonceEntry { expires_at });
            true
        }
        Entry::Vacant(e) => {
            e.insert(NonceEntry { expires_at });
            true
        }
    }
}

async fn cleanup_loop() {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        let map = nonce_map();
        let now = now_secs();
        let before = map.len();
        map.retain(|_, v| v.expires_at > now);
        let cleaned = before - map.len();
        if cleaned > 0 {
            tracing::debug!("[NonceFallback] 清理 {} 条过期 nonce", cleaned);
        }
    }
}
