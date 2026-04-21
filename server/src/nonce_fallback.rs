// server/src/nonce_fallback.rs — 优化版 v2
// ✅ MD-03 FIX: 使用 OccupiedEntry::insert 原地替换，消除竞态窗口

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

/// ✅ MD-03 FIX: 使用 OccupiedEntry::insert 原地替换，持锁内完成，无竞态窗口
pub fn check_and_store(key: &str, ttl_secs: u64) -> bool {
    let map = nonce_map();
    let now = now_secs();
    let expires_at = now + ttl_secs;

    // 容量保护
    if map.len() >= MAX_NONCE_ENTRIES {
        tracing::error!(
            "[NonceFallback] Capacity exceeded ({}), rejecting",
            MAX_NONCE_ENTRIES
        );
        return false;
    }

    use dashmap::mapref::entry::Entry;
    match map.entry(key.to_string()) {
        Entry::Occupied(mut e) => {
            if e.get().expires_at > now {
                // nonce 仍在有效期，拒绝重放
                return false;
            }
            // ✅ 过期：原地替换（持锁，无竞态窗口）
            e.insert(NonceEntry { expires_at });
            true
        }
        Entry::Vacant(e) => {
            // 新 nonce，直接插入
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
            tracing::debug!(
                "[NonceFallback] Cleaned {} expired nonces ({} remaining)",
                cleaned,
                map.len()
            );
        }
    }
}
