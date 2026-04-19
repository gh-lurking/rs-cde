// server/src/nonce_fallback.rs — 优化版 v4

// ✅ CRIT-B FIX: Occupied arm expires_at 比较方向明确（<= now = 已过期可复用）
//               并修复原始代码截断导致的逻辑不完整问题
// ✅ 新增: now 提前绑定为局部变量，避免 borrow 问题
use dashmap::DashMap;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

struct NonceEntry {
    expires_at: u64,
}

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

/// 检查并存储 nonce（基于 DashMap shard 锁，在 match arm 内原子执行）
///
/// DashMap::entry() 持有目标 shard 的写锁直到 match arm 结束：
/// - Occupied arm 内：先检查是否过期，再决定是否复用
/// - Vacant arm：直接插入
/// 返回 true  = nonce 有效（新请求，或已过期 slot 被复用）
/// 返回 false = nonce 仍有效但已存在（重放攻击，拒绝）
pub fn check_and_store(key: &str, ttl_secs: u64) -> bool {
    let map = nonce_map();
    let now = now_secs(); // ✅ 提前绑定，避免 borrow 问题
    let expires_at = now + ttl_secs;

    use dashmap::mapref::entry::Entry;
    match map.entry(key.to_string()) {
        Entry::Occupied(mut e) => {
            // ✅ CRIT-B FIX: 正确比较方向
            // e.get().expires_at <= now  → 该 nonce slot 已过期，可以复用（允许通过）
            // e.get().expires_at >  now  → nonce 仍有效，属于重放攻击（拒绝）
            if e.get().expires_at <= now {
                // 过期 nonce，复用 slot（更新 expires_at），允许通过
                e.insert(NonceEntry { expires_at });
                true
            } else {
                // 未过期 nonce，重放攻击，拒绝
                false
            }
        }

        Entry::Vacant(e) => {
            // 新 nonce，插入并允许通过
            e.insert(NonceEntry { expires_at });
            true
        }
    }
}

/// 定期清理过期 nonce（每 60s 一次）
async fn cleanup_loop() {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        let map = nonce_map();
        let now = now_secs();
        let before = map.len();
        map.retain(|_, v| v.expires_at > now);
        let after = map.len();
        if before != after {
            tracing::debug!("[NonceFallback] Cleaned {} expired nonces", before - after);
        }
    }
}
