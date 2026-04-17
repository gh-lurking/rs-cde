// server/src/cache.rs — Redis 缓存层
//
// ✅ 新增模块：统一管理 /verify 接口的 Redis 缓存
//
// 设计要点：
//   1. 连接池使用 deadpool-redis，支持健康检查 + 自动重连
//   2. /verify 缓存 TTL = 30 秒（VERIFY_CACHE_TTL_SECS，可环境变量覆盖）
//      - 同一 key_hash 在 30s 内重复请求直接走缓存，不查 PostgreSQL
//   3. 吊销/延期接口后立即 DEL 对应缓存 key，保证强一致性
//   4. Redis 不可用时降级到 PostgreSQL（handlers 做 Option 判断）

use deadpool_redis::{Config, Pool, PoolConfig, Runtime, Timeouts};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Redis 连接池类型别名
pub type RedisPool = Pool;

/// /verify 缓存条目
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VerifyCacheEntry {
    pub activation_ts: i64,
    pub expires_at: i64,
    pub revoked: bool,
}

// ── 缓存 TTL ──────────────────────────────────────────────────────────────
fn verify_cache_ttl() -> u64 {
    std::env::var("VERIFY_CACHE_TTL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30)
}

// ── 连接池初始化 ───────────────────────────────────────────────────────────

/// 创建 deadpool-redis 连接池
///
/// # 连接池参数
/// | 参数            | 值    | 说明                                     |
/// |-----------------|-------|------------------------------------------|
/// | max_size        | 32    | 最大连接数（REDIS_POOL_SIZE 覆盖）        |
/// | wait_timeout    | 3s    | 等待空闲连接超时                         |
/// | create_timeout  | 5s    | 建立新连接超时                           |
/// | recycle_timeout | 2s    | 连接健康检查（PING）超时                 |
pub fn init_redis_pool(redis_url: &str) -> Result<RedisPool, deadpool_redis::CreatePoolError> {
    let max_size: usize = std::env::var("REDIS_POOL_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(32);

    let cfg = Config {
        url: Some(redis_url.to_string()),
        pool: Some(PoolConfig {
            max_size,
            timeouts: Timeouts {
                wait: Some(Duration::from_secs(3)),
                create: Some(Duration::from_secs(5)),
                recycle: Some(Duration::from_secs(2)),
            },
            ..Default::default()
        }),
        ..Default::default()
    };

    cfg.create_pool(Some(Runtime::Tokio1))
}

// ── 缓存 key ─────────────────────────────────────────────────────────────

fn cache_key(key_hash: &str) -> String {
    format!("verify:{}", key_hash)
}

// ── 读 ────────────────────────────────────────────────────────────────────

/// 从 Redis 读取 /verify 缓存
/// - 命中 → Some(VerifyCacheEntry)
/// - 未命中 / Redis 故障 → None（调用方 fallback 到 PostgreSQL）
pub async fn get_verify_cache(pool: &RedisPool, key_hash: &str) -> Option<VerifyCacheEntry> {
    let mut conn = pool.get().await.ok()?;
    let raw: Option<String> = conn.get(cache_key(key_hash)).await.ok()?;
    raw.and_then(|s| serde_json::from_str(&s).ok())
}

// ── 写 ────────────────────────────────────────────────────────────────────

/// 将 /verify 结果写入 Redis，SET key value EX ttl
/// 写入失败（Redis 故障）静默忽略
pub async fn set_verify_cache(pool: &RedisPool, key_hash: &str, entry: &VerifyCacheEntry) {
    let Ok(mut conn) = pool.get().await else {
        return;
    };
    let Ok(json) = serde_json::to_string(entry) else {
        return;
    };

    let _: Result<(), _> = redis::cmd("SET")
        .arg(cache_key(key_hash))
        .arg(&json)
        .arg("EX")
        .arg(verify_cache_ttl())
        .query_async(&mut conn)
        .await;
}

// ── 失效 ──────────────────────────────────────────────────────────────────

/// 主动失效某个 key_hash 的 /verify 缓存（DEL）
///
/// 调用场景：
///   - 吊销 License → revoke_license handler
///   - 延长有效期  → extend_license handler
///   - 首次激活    → activate handler
pub async fn invalidate_verify_cache(pool: &RedisPool, key_hash: &str) {
    let Ok(mut conn) = pool.get().await else {
        return;
    };
    let _: Result<i64, _> = conn.del(cache_key(key_hash)).await;
    tracing::debug!("Invalid Redis Cache: verify:{}", &key_hash[..8]);
}
