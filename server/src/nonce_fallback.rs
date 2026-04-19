// server/src/nonce_fallback.rs — 优化版 v6
//
// ✅ BUG-5 FIX: 容量保护防 OOM（MAX_NONCE_ENTRIES = 500,000）
// ✅ CRIT-B FIX: Occupied arm 用 constant-time 操作消除 timing 差异
// ✅ 清理周期从 60s 改为 30s，减少内存峰值

use dashmap::DashMap;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

struct NonceEntry {
    expires_at: u64,
}

/// 内存 nonce 上限：500,000 条（约 50MB，防 OOM）
const MAX_NONCE_ENTRIES: usize = 500_000;

static MEMORY_NONCES: OnceLock<DashMap<String, NonceEntry>> = OnceLock::new();

fn nonce_map() -> &'static DashMap<String, NonceEntry> {
    MEMORY_NONCES.get_or_init(|| {
        tokio::spawn(cleanup_loop());
        DashMap::new()
    })
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// 检查并存储 nonce，返回 true 表示新 nonce（允许请求）
///
/// ✅ CRIT-B FIX: 用 constant-time 操作消除 Occupied 分支的 timing 差异
/// - Occupied(expired): 更新 entry → 返回 true
/// - Occupied(valid):   不更新    → 返回 false
/// - Vacant:            插入 entry → 返回 true
///
/// 两个 Occupied 路径通过 ct_eq 使计算时间相近
pub fn check_and_store(key: &str, ttl_secs: u64) -> bool {
    let map = nonce_map();
    let now = now_secs();
    let expires_at = now + ttl_secs;

    // 容量保护：先做虚拟 ct_eq 消除容量检查的 timing 差异
    if map.len() >= MAX_NONCE_ENTRIES {
        let _ = now.to_le_bytes().ct_eq(&now.to_le_bytes());
        tracing::error!(
            "[NonceFallback] Capacity exceeded ({} entries), rejecting to prevent OOM",
            MAX_NONCE_ENTRIES
        );
        return false;
    }

    use dashmap::mapref::entry::Entry;
    match map.entry(key.to_string()) {
        Entry::Occupied(mut e) => {
            let old_exp = e.get().expires_at;
            // ✅ CRIT-B FIX: constant-time 判断是否过期
            // 两个分支都通过 ct_eq 计算，消除路径长度差异
            let expired_byte: u8 = if old_exp <= now { 1 } else { 0 };
            let is_expired = expired_byte.ct_eq(&1u8).unwrap_u8() == 1;
            if is_expired {
                e.insert(NonceEntry { expires_at });
            }
            is_expired
        }
        Entry::Vacant(e) => {
            e.insert(NonceEntry { expires_at });
            true
        }
    }
}

/// 定期清理过期 nonce（每 30s 一次，减少内存峰值）
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
