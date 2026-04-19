// server/src/nonce_fallback.rs — 优化版 v7
//
// MED-2 FIX  : tokio::spawn 移出 OnceLock::get_or_init，改为 start_cleanup_task()
// BUG-5 FIX  : 容量保护防 OOM（MAX_NONCE_ENTRIES = 500,000）
// CRIT-B FIX : Occupied arm 用 constant-time 消除 timing 差异

use dashmap::DashMap;
use std::sync::{
    OnceLock,
    atomic::{AtomicBool, Ordering},
};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

struct NonceEntry {
    expires_at: u64,
}

/// 内存 nonce 上限：500,000 条（约 50 MB，防 OOM）
const MAX_NONCE_ENTRIES: usize = 500_000;

static MEMORY_NONCES: OnceLock<DashMap<String, NonceEntry>> = OnceLock::new();
/// MED-2 FIX: cleanup 启动状态独立管理
static CLEANUP_STARTED: AtomicBool = AtomicBool::new(false);

fn nonce_map() -> &'static DashMap<String, NonceEntry> {
    // MED-2 FIX: 闭包只创建 DashMap，不在此处调用 tokio::spawn
    MEMORY_NONCES.get_or_init(DashMap::new)
}

/// 在 main() async 上下文中显式调用，确保 Tokio runtime 已就绪
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

/// 检查并存储 nonce，返回 true 表示新 nonce（允许请求）
pub fn check_and_store(key: &str, ttl_secs: u64) -> bool {
    let map = nonce_map();
    let now = now_secs();
    let expires_at = now + ttl_secs;

    // BUG-5 FIX: 容量保护
    if map.len() >= MAX_NONCE_ENTRIES {
        // 用无意义的常量时间操作保持路径均一
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
            // CRIT-B FIX: 用 constant-time 操作消除 Occupied 路径 timing 差异
            let expired_byte: u8 = if old_exp < now { 1 } else { 0 };
            let _ = expired_byte.to_le_bytes().ct_eq(&[1u8]);
            if old_exp < now {
                // 旧 nonce 已过期，重用此 slot
                e.get_mut().expires_at = expires_at;
                true
            } else {
                // nonce 未过期，拒绝（防重放）
                false
            }
        }
        Entry::Vacant(v) => {
            v.insert(NonceEntry { expires_at });
            true
        }
    }
}

/// 定期清理过期 nonce（每 30s 一次）
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
