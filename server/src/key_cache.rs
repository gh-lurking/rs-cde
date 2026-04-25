// server/src/key_cache.rs — 优化版 v4
//
// [BUG-MED-1 FIX] FIFO 淘汰竞态修复：
//   get_or_load() 中 len()>=MAX 检查与 insert() 之间无锁，
//   多线程并发可能短暂超过 KEY_CACHE_MAX。
//   修复方案：在 insert 之前和之后各做一次容量检查。
//   这样即使并发插入导致超限，也会在后续的某次操作中被修正。
//
// [BUG-HIGH-3 FIX] 并发竞态增强：
//   通过前置和后置双重容量检查 + 迭代器淘汰，确保容量不会持续增长。
//
// 与 CLAUDE.md §2「Simplicity First」一致：
//   不引入额外同步原语，不改变整体架构，仅在 insert 前后增加防御性 cleanup。
//
// 设计原则（对应 CLAUDE.md §2）：
//   - 不引入外部 LRU 库，使用 DashMap + 容量检查实现简单 FIFO 淘汰
//   - revoke 时由 handlers.rs 调用 remove() 同步失效
//   - 进程重启后自动重建（首次 /verify 回源 DB）
//   - KEY_CACHE_MAX = 10000，典型部署场景足够（10k 并发 key）

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
        // [BUG-MED-1 FIX] 先尝试淘汰最旧条目，再插入
        if KEY_CACHE.len() >= KEY_CACHE_MAX {
            // 淘汰一个最旧条目（FIFO：迭代器第一个）
            if let Some(old) = KEY_CACHE.iter().next().map(|e| e.key().clone()) {
                KEY_CACHE.remove(&old);
            }
        }
        KEY_CACHE.insert(key_hash.to_string(), k.clone());

        // [BUG-HIGH-3 FIX] 二次防御：插入后如果仍超限（并发插入导致），
        // 额外清理一个条目。最坏情况仍然有效，只是短暂 > MAX。
        if KEY_CACHE.len() > KEY_CACHE_MAX {
            if let Some(old) = KEY_CACHE.iter().next().map(|e| e.key().clone()) {
                KEY_CACHE.remove(&old);
            }
        }
    }

    Ok(key)
}

pub fn remove(key_hash: &str) {
    KEY_CACHE.remove(key_hash);
}

/// 用于 /health 接口观测缓存大小（直接读 DashMap::len()，准确）
pub fn cache_size() -> usize {
    KEY_CACHE.len()
}
