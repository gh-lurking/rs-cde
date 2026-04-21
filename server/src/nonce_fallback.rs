// server/src/nonce_fallback.rs -- 优化版 v3
//
// BUG-02 FIX: check_and_store 逻辑修正
//   原始错误: Occupied 分支 expires_at > now 时返回 true (允许重放!)
//   修正后:   expires_at > now -> nonce 有效 -> 返回 false (拦截重放)
//             expires_at <= now -> nonce 过期 -> 覆盖并返回 true (新请求)
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

/// BUG-02 FIX: Entry API -- check + insert 原子化，避免 TOCTOU
///
/// 返回 true  -> nonce 首次出现（或已过期），请求合法
/// 返回 false -> nonce 在有效期内，重放攻击，拒绝
pub fn check_and_store(key: &str, ttl_secs: u64) -> bool {
    let map = nonce_map();
    let now = now_secs();
    let expires_at = now + ttl_secs;

    if map.len() >= MAX_NONCE_ENTRIES {
        tracing::error!("[NonceFallback] 内存已满，拒绝新 nonce");
        return false;
    }

    use dashmap::mapref::entry::Entry;
    match map.entry(key.to_string()) {
        Entry::Occupied(mut e) => {
            if e.get().expires_at > now {
                // BUG-02 FIX: nonce 仍有效 -> 重放攻击 -> 拒绝
                return false;
            }
            // nonce 已过期 -> 视为新请求，覆盖
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
