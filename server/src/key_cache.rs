// server/src/key_cache.rs — 优化版 v2
//
// 进程内 key_hash → key 映射缓存（[OPT-3]）
//
// 设计原则（对应 CLAUDE.md §2 「Simplicity First」）：
// - 不引入外部 LRU 库，使用 DashMap + 容量检查实现简单 FIFO 淘汰
// - revoke 时由 handlers.rs 调用 remove() 同步失效
// - 进程重启后自动重建（首次 /verify 回源 DB）
// - KEY_CACHE_MAX = 10000，典型部署场景足够（10k 并发 key）
//
// [BUG-KEY-1 FIX] 废弃 CACHE_SIZE AtomicUsize，直接用 KEY_CACHE.len()
// 与 CLAUDE.md §2「Simplicity First」一致：
// 维护冗余计数器比直接读 DashMap::len() 更复杂且引入竞态

use dashmap::DashMap;
use once_cell::sync::Lazy;

const KEY_CACHE_MAX: usize = 10_000;

static KEY_CACHE: Lazy<DashMap<String, String>> = Lazy::new(DashMap::new);

pub async fn get_or_load(
    key_hash: &str,
    pool: &crate::db::DbPool,
) -> Result<Option<String>, sqlx::Error> {
    // 缓存命中（热路径，无 DB 查询）
    if let Some(entry) = KEY_CACHE.get(key_hash) {
        return Ok(Some(entry.clone()));
    }

    // 缓存未命中，查 DB
    let key = crate::db::get_key_only(pool, key_hash).await?;

    if let Some(ref k) = key {
        // [BUG-KEY-1 FIX] 直接读 len()，无需维护 AtomicUsize
        if KEY_CACHE.len() >= KEY_CACHE_MAX {
            if let Some(old) = KEY_CACHE.iter().next().map(|e| e.key().clone()) {
                KEY_CACHE.remove(&old);
            }
        }
        KEY_CACHE.insert(key_hash.to_string(), k.clone());
    }

    Ok(key)
}

pub fn remove(key_hash: &str) {
    KEY_CACHE.remove(key_hash);
    // [BUG-KEY-1 FIX] 不需要手动维护计数器
}

/// 用于 /health 接口观测缓存大小（直接读 DashMap::len()，准确）
pub fn cache_size() -> usize {
    KEY_CACHE.len()
}
