// server/src/key_cache.rs
//
// 进程内 key_hash → key 映射缓存（[OPT-3]）
//
// 设计原则（对应 CLAUDE.md §2 「Simplicity First」）：
// - 不引入外部 LRU 库，使用 DashMap + 容量检查实现简单 FIFO 淘汰
// - revoke 时由 handlers.rs 调用 remove() 同步失效
// - 进程重启后自动重建（首次 /verify 回源 DB）
// - KEY_CACHE_MAX = 10000，典型部署场景足够（10k 并发 key）

use dashmap::DashMap;
use once_cell::sync::Lazy;
use std::sync::atomic::{AtomicUsize, Ordering};

/// 进程内最大缓存条目数
/// 超过后随机淘汰（DashMap 无序，等效随机），不阻塞写入
const KEY_CACHE_MAX: usize = 10_000;

static KEY_CACHE: Lazy<DashMap<String, String>> = Lazy::new(DashMap::new);
static CACHE_SIZE: AtomicUsize = AtomicUsize::new(0);

/// 从缓存获取 key；缓存未命中则查 DB 并写入缓存
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
        // 容量检查：超过上限时随机淘汰一个条目（简单策略，不影响正确性）
        if CACHE_SIZE.load(Ordering::Relaxed) >= KEY_CACHE_MAX {
            if let Some(old_entry) = KEY_CACHE.iter().next().map(|e| e.key().clone()) {
                KEY_CACHE.remove(&old_entry);
                CACHE_SIZE.fetch_sub(1, Ordering::Relaxed);
            }
        }
        KEY_CACHE.insert(key_hash.to_string(), k.clone());
        CACHE_SIZE.fetch_add(1, Ordering::Relaxed);
    }

    Ok(key)
}

/// revoke 时同步从缓存移除，防止已撤销 key 继续通过 HMAC 验证
pub fn remove(key_hash: &str) {
    if KEY_CACHE.remove(key_hash).is_some() {
        CACHE_SIZE.fetch_sub(1, Ordering::Relaxed);
    }
}

/// 用于 /health 接口观测缓存大小
pub fn cache_size() -> usize {
    CACHE_SIZE.load(Ordering::Relaxed)
}
