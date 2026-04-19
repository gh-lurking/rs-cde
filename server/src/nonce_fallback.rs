// server/src/nonce_fallback.rs — 新增文件
//
// ✅ OPT-MAJOR-4: Redis 不可用时的内存 nonce 降级
// 使用 DashMap 实现线程安全的 nonce 存储，后台任务定期清理过期条目
use dashmap::DashMap;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

struct NonceEntry {
    expires_at: u64,
}

static MEMORY_NONCES: OnceLock<DashMap<String, NonceEntry>> = OnceLock::new();

fn nonce_map() -> &'static DashMap<String, NonceEntry> {
    MEMORY_NONCES.get_or_init(|| {
        // 启动后台清理任务
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

/// 检查并存储 nonce（原子操作：检查不存在→插入）
/// 返回 true 表示 nonce 合法（首次使用），false 表示重放
pub fn check_and_store(key: &str, ttl_secs: u64) -> bool {
    let map = nonce_map();
    let now = now_secs();
    let expires_at = now + ttl_secs;

    // DashMap::entry().or_insert_with() 保证原子性
    use dashmap::mapref::entry::Entry;
    match map.entry(key.to_string()) {
        Entry::Occupied(e) => {
            if e.get().expires_at <= now {
                // 已过期条目：允许复用（视为新 nonce）
                e.replace_entry(NonceEntry { expires_at });
                true
            } else {
                // 未过期：重放拒绝
                false
            }
        }
        Entry::Vacant(e) => {
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
