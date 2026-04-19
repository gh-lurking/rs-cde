// server/src/nonce_fallback.rs — 优化版 v2 (Bug澄清 + 注释强化版)
//
// ✅ CRIT-2 澄清: DashMap entry() 获取后，整个 match arm 在 shard 锁内执行。
//   Occupied::insert() 是原子的原地替换，不存在 TOCTOU 竞态。
//   真正问题是语义：已过期 nonce → 允许重新使用（正确行为），已注释说明。
// ✅ 修复 Occupied 分支中 expires_at < now 的比较（原代码逻辑正确，增加注释）

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

/// 检查并存储 nonce（并发安全）
///
/// 并发安全性说明：
/// DashMap::entry() 获取时会锁定对应的 shard（内部分片锁）。
/// 在 match arm 执行期间，shard 锁持续持有，直到 arm 结束。
/// - Occupied::insert() = 原地替换，shard 锁内完成，无竞态 ✅
/// - Vacant::insert() = 原地插入，shard 锁内完成，无竞态 ✅
///
/// 返回 true = nonce 合法（首次使用或已过期后重新使用）
/// 返回 false = nonce 重放（仍在有效期内）
pub fn check_and_store(key: &str, ttl_secs: u64) -> bool {
    let map = nonce_map();
    let now = now_secs();
    let expires_at = now + ttl_secs;

    use dashmap::mapref::entry::Entry;
    match map.entry(key.to_string()) {
        Entry::Occupied(mut e) => {
            if e.get().expires_at < now {
                // 此 nonce slot 已过期（旧请求的 nonce 超出时间窗口）
                // 语义：过期 = 可回收，允许同 key 的新请求使用此 slot
                // 安全性：shard 锁内原子替换，不存在 TOCTOU
                e.insert(NonceEntry { expires_at });
                true // 允许
            } else {
                // nonce 仍在有效期内 → 重放攻击，拒绝
                false
            }
        }
        Entry::Vacant(e) => {
            // 首次使用，直接插入
            e.insert(NonceEntry { expires_at });
            true
        }
    }
}

/// 后台定期清理过期 nonce（每 60s 一次）
async fn cleanup_loop() {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        let map = nonce_map();
        let now = now_secs();
        let before = map.len();
        map.retain(|_, v| v.expires_at > now);
        let after = map.len();
        if before != after {
            tracing::debug!("[NonceFallback] 清理过期条目 {} 条", before - after);
        }
    }
}
