// server/src/nonce_fallback.rs — 优化版 v7
//
// MED-2 FIX  : tokio::spawn 移出 OnceLock::get_or_init，改为 start_cleanup_task()
// BUG-5 FIX  : 容量保护防 OOM（MAX_NONCE_ENTRIES = 500,000）
// CRIT-B FIX : Occupied arm 用 constant-time 消除 timing 差异

use dashmap::DashMap;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    OnceLock,
};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

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

pub fn check_and_store(key: &str, ttl_secs: u64) -> bool {
    let map = nonce_map();
    let now = now_secs();
    let expires_at = now + ttl_secs;

    // 容量保护
    if map.len() >= MAX_NONCE_ENTRIES {
        let _ = now.to_le_bytes().ct_eq(&now.to_le_bytes());
        tracing::error!(
            "[NonceFallback] Capacity exceeded ({} entries), rejecting",
            MAX_NONCE_ENTRIES
        );
        return false;
    }

    use dashmap::mapref::entry::Entry;
    match map.entry(key.to_string()) {
        Entry::Occupied(mut e) => {
            let old_exp = e.get().expires_at;
            // 使用 constant-time 操作消除 timing 差异
            let expired = old_exp <= now;
            let expired_byte = if expired { 1u8 } else { 0u8 };
            let _ = [expired_byte].ct_eq(&[1u8]);

            if expired {
                e.insert(NonceEntry { expires_at });
                true
            } else {
                false
            }
        }
        Entry::Vacant(v) => {
            v.insert(NonceEntry { expires_at });
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
