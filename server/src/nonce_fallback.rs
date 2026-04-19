// server/src/nonce_fallback.rs — 优化版 v3
// ✅ CRIT-2 分析: DashMap entry() 持有 shard 写锁，Occupied arm 内操作是原子的
// ✅ 修复: 明确注释说明 Occupied::insert() 语义，消除误导性注释
// ✅ 修复: cleanup_loop 使用 tokio::spawn，已在 nonce_map() 初始化时启动
use dashmap::DashMap;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

struct NonceEntry {
    expires_at: u64,
}

static MEMORY_NONCES: OnceLock<DashMap<String, NonceEntry>> = OnceLock::new();

fn nonce_map() -> &'static DashMap<String, NonceEntry> {
    MEMORY_NONCES.get_or_init(|| {
        // cleanup_loop 在独立 tokio task 中运行
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

/// 检查并存储 nonce（原子操作，基于 DashMap shard 锁）
///
/// DashMap::entry() 持有目标 shard 的写锁直到 match arm 结束，保证原子性。
/// 在 match arm 内，get() + insert() 在同一锁范围内执行，无 TOCTOU。
///
/// 返回 true  = nonce 有效（新 nonce 或过期 nonce slot 被复用）
/// 返回 false = nonce 已存在且未过期（重放攻击，拒绝）
pub fn check_and_store(key: &str, ttl_secs: u64) -> bool {
    let map = nonce_map();
    let now = now_secs();
    let expires_at = now + ttl_secs;

    use dashmap::mapref::entry::Entry;
    match map.entry(key.to_string()) {
        Entry::Occupied(mut e) => {
            if e.get().expires_at < now {
                // 过期 slot 复用（在同一 shard 写锁内，原子）
                // Occupied::insert() 替换当前值，语义明确
                e.insert(NonceEntry { expires_at });
                true // 过期后被复用，允许通过
            } else {
                // 未过期 = 重放攻击，拒绝
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
            tracing::debug!("[NonceFallback] 清理过期 nonce {} 条", before - after);
        }
    }
}
