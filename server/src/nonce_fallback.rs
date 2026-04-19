// server/src/nonce_fallback.rs — 优化版 v5
//
// ✅ BUG-5 FIX: 增加 MAX_NONCE_ENTRIES 容量上限（500,000），防 OOM 攻击
//   攻击场景：Redis 故障期间，攻击者用不同 sig 持续发请求，耗尽内存
// ✅ 清理频率从 60s 提高到 30s，减少过期记录堆积
// ✅ 保留原有: CRIT-B FIX（Occupied arm 正确比较方向）

use dashmap::DashMap;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

struct NonceEntry {
    expires_at: u64,
}

/// 内存 nonce 容量上限：500,000 条（约 50MB，作为软限制）
/// 超出时拒绝新 nonce 以保护内存安全
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

/// 检查并存储 nonce（DashMap entry 持有 shard 写锁，在 match arm 内原子执行）
///
/// ⚠️  此函数必须保持为同步函数（非 async）
///    DashMap entry guard 不能跨 .await 点持有
///
/// 返回 true  = 新 nonce，允许通过
/// 返回 false = 重放攻击（nonce 仍有效）或容量溢出
pub fn check_and_store(key: &str, ttl_secs: u64) -> bool {
    let map = nonce_map();
    let now = now_secs();
    let expires_at = now + ttl_secs;

    // ✅ BUG-5 FIX: 容量保护
    // map.len() 非精确（DashMap 并发下略有偏差），但足够作为软限制
    if map.len() >= MAX_NONCE_ENTRIES {
        tracing::error!(
            "[NonceFallback] Capacity exceeded ({} entries), rejecting nonce to prevent OOM",
            MAX_NONCE_ENTRIES
        );
        return false;
    }

    use dashmap::mapref::entry::Entry;
    match map.entry(key.to_string()) {
        Entry::Occupied(mut e) => {
            // ✅ CRIT-B FIX: 正确比较方向
            // expires_at <= now → nonce 已过期，可以复用（允许通过）
            // expires_at > now  → nonce 仍有效，重放攻击（拒绝）
            if e.get().expires_at <= now {
                e.insert(NonceEntry { expires_at });
                true
            } else {
                false
            }
        }
        Entry::Vacant(e) => {
            e.insert(NonceEntry { expires_at });
            true
        }
    }
}

/// 定期清理过期 nonce（每 30s 一次，比原来 60s 更频繁）
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
