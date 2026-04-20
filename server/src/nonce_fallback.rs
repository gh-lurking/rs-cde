// server/src/nonce_fallback.rs — 修复无意义比较版
// ✅ BUG-05 FIX: 移除无意义的 ct_eq 比较
// ✅ BUG-5 FIX: 容量保护防 OOM
use dashmap::DashMap;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    OnceLock,
};
use std::time::{SystemTime, UNIX_EPOCH};

struct NonceEntry {
    expires_at: u64,
}

const MAX_NONCE_ENTRIES: usize = 500_000;

static MEMORY_NONCES: OnceLock<DashMap<String, NonceEntry>> = OnceLock::new();
static CLEANUP_STARTED: AtomicBool = AtomicBool::new(false);

fn nonce_map() -> &'static DashMap<String, NonceEntry> {
    MEMORY_NONCES.get_or_init(DashMap::new)
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

/// ✅ FIX: 移除无意义的 ct_eq，直接返回
pub fn check_and_store(key: &str, ttl_secs: u64) -> bool {
    let map = nonce_map();
    let now = now_secs();
    let expires_at = now + ttl_secs;

    // 容量保护
    if map.len() >= MAX_NONCE_ENTRIES {
        tracing::error!(
            "[NonceFallback] Capacity exceeded ({} entries), rejecting",
            MAX_NONCE_ENTRIES
        );
        return false;
    }

    use dashmap::mapref::entry::Entry;
    match map.entry(key.to_string()) {
        Entry::Occupied(e) => {
            let old_exp = e.get().expires_at;
            if old_exp > now {
                return false; // nonce 仍有效，重放
            }
            // 过期，移除旧条目
            e.remove();
            // 继续插入
        }
        Entry::Vacant(_) => {}
    }

    // 插入新 nonce
    map.insert(key.to_string(), NonceEntry { expires_at });
    true
}

async fn cleanup_loop() {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        let map = nonce_map();
        let now = now_secs();
        let before = map.len();
        map.retain(|_, v| v.expires_at > now);
        let after = map.len();
        if before != after {
            tracing::debug!(
                "[NonceFallback] Cleaned {} expired nonces ({} remaining)",
                before - after,
                after
            );
        }
    }
}
