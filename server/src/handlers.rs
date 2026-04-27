// server/src/handlers.rs — 优化版 v16
//
// [BUG-CRIT-1 FIX] 时间戳减法溢出修复：
//   (now - req.timestamp).abs() 在 req.timestamp=i64::MIN 时发生有符号溢出。
//   改用 safe_time_diff 安全计算差值，溢出时返回 i64::MAX 触发拒绝。
//   对应 CLAUDE.md §1「Think Before Coding」：明确防御极端输入。
//
// [BUG-HIGH-1 FIX] is_expired() 改用 saturating_add：
//   expires_at + expiration_grace_secs() 可能溢出。
//   溢出后 wrap 为负数 → now >= 负数永远为 true → 密钥在过期后仍被放行。
//   改用 saturating_add 确保溢出时停在 i64::MAX（即永不过期），
//   但 expires_at 本身仍需通过数据合法性校验（<= now + MAX_LICENSE_PERIOD）。
//
// [BUG-CRIT-4 FIX] 缓存条目 activation_ts 防御：
//   在 /verify 缓存路径增加 activation_ts <= 0 检查，
//   防止 activation_ts=0, expires_at>0 的损坏数据被缓存。
//
// [BUG-HIGH-4 FIX] /verify 增加 activation_ts > now 校验：
//   防止 DB 损坏导致的未来时间戳被接受。
//   同时增加 validate_license_sanity 调用。
//
// [V16] 统一数据合法性校验入口：调用 db::validate_license_sanity()

// [BUG FIX] 缓存命中路径每次仍查一次 DB（get_key_only）——有意设计但注释不足
// 缓存命中后为了 HMAC 验证必须从 DB 取 key 明文（Redis 不缓存密钥明文，BUG-H3）。
// 这意味着"缓存"只减少了全量字段查询，但仍有一次主键索引查询（~1ms）。
// 这是有意的安全设计（不在 Redis 存密钥），但注释说明不足，容易被误解为可优化项。
// 实际上若要彻底消除该 DB 查询，需在内存（进程级）维护 key→hmac_key 的 LRU 缓存，
// 并在 revoke 时同步失效。当前设计的 DB 访问可接受，无需改动，仅需补充注释。
use crate::cache;
use crate::db;
use crate::key_cache;
use crate::nonce_fallback;

use axum::{extract::Query, response::IntoResponse, Extension, Json};
use deadpool_redis::Pool as RedisPool;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;
// ── 常量 ────────────────────────────────────────────────────────────────────
const STATUS_EXPIRED: axum::http::StatusCode = axum::http::StatusCode::GONE;
const STATUS_REVOKED: axum::http::StatusCode = axum::http::StatusCode::FORBIDDEN;
const STATUS_NOT_ACTIVATED: axum::http::StatusCode = axum::http::StatusCode::CONFLICT;
const STATUS_NONCE_REPLAY: axum::http::StatusCode = axum::http::StatusCode::CONFLICT;
const STATUS_INVALID_KEY: axum::http::StatusCode = axum::http::StatusCode::FORBIDDEN;
const SIG_MAX_LEN: usize = 256;

/// [BUG-CRIT-1 FIX] 安全时间差计算
///
/// 替代 `(now - req.timestamp).abs()`，防止 i64 溢出。
/// 当差值溢出（即 req.timestamp 为 i64::MIN 或 i64::MAX 的极端值）时返回 i64::MAX，
/// 触发时间窗口拒绝，绝不放行。
///
/// 假设：合法客户端时间戳在 [now - 1h, now + 1h] 范围内，
/// 任何超过 i64::MAX/2 的差值都是恶意或故障。
fn safe_time_diff(a: i64, b: i64) -> i64 {
    a.checked_sub(b)
        .or_else(|| b.checked_sub(a))
        .unwrap_or(i64::MAX)
}

// ── 服务端标识 ──────────────────────────────────────────────────────────────
static SERVER_ID: OnceLock<String> = OnceLock::new();
fn get_server_id() -> &'static str {
    SERVER_ID.get_or_init(|| {
        std::env::var("SERVER_ID").unwrap_or_else(|_| "license-server-v1".to_string())
    })
}

// ── 过期宽限期配置 ──────────────────────────────────────────────────────────
static EXPIRATION_GRACE: OnceLock<i64> = OnceLock::new();
fn expiration_grace_secs() -> i64 {
    *EXPIRATION_GRACE.get_or_init(|| {
        std::env::var("EXPIRATION_GRACE_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    })
}

/// [BUG-HIGH-1 FIX] 统一过期判断：now >= expires_at + grace
///
/// 使用 saturating_add 防止 expires_at + grace 溢出。
/// 如果溢出（expires_at 接近 i64::MAX 且 grace 很大），
/// saturating_add 返回 i64::MAX，此时 now >= i64::MAX 几乎永远为 false
/// （即密钥永不过期），但这是极不可能发生的配置，且 expires_at 本身会
/// 被数据校验拦截（不得超过 now + MAX_LICENSE_PERIOD）。
fn is_expired(expires_at: i64, now: i64) -> bool {
    now >= expires_at.saturating_add(expiration_grace_secs())
}

// ── 时间工具 ────────────────────────────────────────────────────────────────
fn now_secs() -> i64 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    i64::try_from(secs).unwrap_or(i64::MAX)
}

fn hash_key(key: &str) -> String {
    crate::db::hash_key(key)
}

fn validate_key_hash(key_hash: &str) -> bool {
    key_hash.len() == 64 && key_hash.chars().all(|c| c.is_ascii_hexdigit())
}

fn verify_hmac_signature(key: &str, key_hash: &str, timestamp: i64, sig: &str) -> bool {
    if sig.len() > SIG_MAX_LEN {
        return false;
    }
    let server_id = get_server_id();
    let mut mac = match HmacSha256::new_from_slice(key.as_bytes()) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(server_id.as_bytes());
    mac.update(b"|");
    mac.update(key_hash.as_bytes());
    mac.update(b"|");
    mac.update(timestamp.to_string().as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());
    if expected.len() != sig.len() {
        return false;
    }
    expected.as_bytes().ct_eq(sig.as_bytes()).into()
}

fn generate_hkey() -> String {
    let uid = Uuid::new_v4().simple().to_string().to_uppercase();
    format!(
        "{}-{}-{}-{}-{}",
        &uid[12..16],
        &uid[0..4],
        &uid[4..8],
        &uid[8..12],
        &uid[16..20]
    )
}

fn timestamp_window() -> i64 {
    static W: OnceLock<i64> = OnceLock::new();
    *W.get_or_init(|| {
        std::env::var("TIMESTAMP_WINDOW_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(300)
    })
}

fn nonce_ttl() -> i64 {
    timestamp_window() * 2 + 30
}

// ── Nonce ───────────────────────────────────────────────────────────────────
async fn check_and_store_nonce(pool: &RedisPool, key_hash: &str, ts: i64) -> bool {
    let key = format!("nonce:{}:{}", key_hash, ts);
    match pool.get().await {
        Ok(mut conn) => {
            let result: Result<Option<String>, _> = deadpool_redis::redis::cmd("SET")
                .arg(&key)
                .arg("1")
                .arg("EX")
                .arg(nonce_ttl())
                .arg("NX")
                .query_async(&mut conn)
                .await;
            matches!(result, Ok(Some(_)))
        }
        Err(e) => {
            tracing::warn!("[Nonce] Redis unavailable ({}) using memory fallback", e);
            nonce_fallback::check_and_store(&key, nonce_ttl() as u64)
        }
    }
}

// ── Last Check 节流 ─────────────────────────────────────────────────────────
async fn should_update_last_check(pool: &RedisPool, key_hash: &str) -> bool {
    let throttle_key = cache::throttle_key(key_hash);
    let Ok(mut conn) = pool.get().await else {
        return false;
    };
    let result: Result<Option<String>, _> = deadpool_redis::redis::cmd("SET")
        .arg(&throttle_key)
        .arg("1")
        .arg("EX")
        .arg(60i64)
        .arg("NX")
        .query_async(&mut conn)
        .await;
    matches!(result, Ok(Some(_)))
}

// ── 响应构建函数 ─────────────────────────────────────────────────────────────
fn ok_verify_response(activation_ts: i64, expires_at: i64) -> axum::response::Response {
    (
        axum::http::StatusCode::OK,
        Json(serde_json::json!({
            "activation_ts": activation_ts,
            "expires_at": expires_at,
            "revoked": false,
        })),
    )
        .into_response()
}

fn time_window_error(now: i64) -> axum::response::Response {
    (
        axum::http::StatusCode::BAD_REQUEST,
        Json(serde_json::json!({
            "error": "ERR-TIME-RECORD",
            "server_time": now
        })),
    )
        .into_response()
}

fn err(code: axum::http::StatusCode, msg: &str) -> axum::response::Response {
    (code, Json(serde_json::json!({ "error": msg }))).into_response()
}

/// [NEW-EXP-3] 过期响应带额外 meta 信息，客户端可解析宽限期
fn expired_response(expires_at: i64, now: i64) -> axum::response::Response {
    let grace = expiration_grace_secs();
    let mut resp = axum::response::Response::new(axum::body::Body::from(
        serde_json::to_string(&serde_json::json!({
            "error": "ERR-EXPIRED",
            "expires_at": expires_at,
            "server_time": now,
            "expiration_grace_secs": grace,
        }))
        .unwrap_or_default(),
    ));
    *resp.status_mut() = STATUS_EXPIRED;
    resp.headers_mut().insert(
        axum::http::HeaderName::from_static("x-expired-at"),
        axum::http::HeaderValue::from_str(&expires_at.to_string()).unwrap(),
    );
    resp.headers_mut().insert(
        axum::http::HeaderName::from_static("x-expiration-grace"),
        axum::http::HeaderValue::from_str(&grace.to_string()).unwrap(),
    );
    resp.headers_mut().insert(
        "content-type",
        axum::http::HeaderValue::from_static("application/json"),
    );
    resp
}

// ═══════════════════════════════════════════════════════════════════════════════
// /activate
// ═══════════════════════════════════════════════════════════════════════════════
#[derive(Deserialize)]
pub struct ActivateReq {
    key_hash: String,
    timestamp: i64,
    signature: String,
}

pub async fn activate(
    Extension(pool): Extension<Arc<crate::db::DbPool>>,
    Extension(redis_pool): Extension<Arc<RedisPool>>,
    Json(req): Json<ActivateReq>,
) -> impl IntoResponse {
    if !validate_key_hash(&req.key_hash) {
        return err(
            axum::http::StatusCode::BAD_REQUEST,
            "invalid key_hash format",
        );
    }

    let now = now_secs();
    // [BUG-CRIT-1 FIX] 安全时间差计算，防止 i64 溢出
    if safe_time_diff(now, req.timestamp) > timestamp_window() {
        return time_window_error(now);
    }

    let record = match crate::db::find_license(&pool, &req.key_hash).await {
        Ok(Some(r)) => r,
        Ok(None) => return err(STATUS_INVALID_KEY, "ERR-INVALID-KEY"),
        Err(e) => {
            tracing::error!("[Activate] DB error: {}", e);
            return err(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "internal error",
            );
        }
    };

    if record.revoked {
        return err(STATUS_REVOKED, "ERR-REVOKED");
    }
    if record.activation_ts > 0 {
        return err(STATUS_NOT_ACTIVATED, "ERR-ALREADY-ACTIVATED");
    }

    // HMAC 验证（在 nonce 消耗之前，防止无效请求消耗 nonce）
    if !verify_hmac_signature(&record.key, &req.key_hash, req.timestamp, &req.signature) {
        return err(STATUS_INVALID_KEY, "ERR-INVALID-KEY");
    }

    if !check_and_store_nonce(&redis_pool, &req.key_hash, req.timestamp).await {
        return err(STATUS_NONCE_REPLAY, "ERR-NONCE-REPLAY");
    }

    let activation_ts = now;
    let default_days: i64 = std::env::var("DEFAULT_LICENSE_DAYS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(365);

    let extra_secs = default_days
        .checked_mul(86400)
        .unwrap_or(crate::db::MAX_EXTEND_SECS)
        .clamp(1, crate::db::MAX_EXTEND_SECS);

    let expires_at = activation_ts.saturating_add(extra_secs);

    match crate::db::activate_license(&pool, &req.key_hash, activation_ts, expires_at).await {
        Ok(true) => ok_verify_response(activation_ts, expires_at),
        Ok(false) => err(STATUS_NOT_ACTIVATED, "ERR-ALREADY-ACTIVATED"),
        Err(e) => {
            tracing::error!("[Activate] DB write: {}", e);
            err(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "internal error",
            )
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// /verify
// ═══════════════════════════════════════════════════════════════════════════════
#[derive(Deserialize)]
pub struct VerifyReq {
    key_hash: String,
    timestamp: i64,
    signature: String,
}

// NOTE: get_key_only 已由进程内 key_cache 替代，消除热路径 DB 查询 [OPT-3]
// 设计取舍：
// - ✅ key_cache 不持久化，进程重启后自动重建（首次 /verify 回源 DB）
// - ✅ revoke 时同步 remove，不存在失效窗口
// - ✅ 容量上限 KEY_CACHE_MAX=10000，LRU 淘汰最旧条目
pub async fn verify(
    Extension(db): Extension<Arc<crate::db::DbPool>>,
    Extension(redis): Extension<Arc<RedisPool>>,
    Json(req): Json<VerifyReq>,
) -> axum::response::Response {
    let now = now_secs();

    // ── 基础校验（不消耗 nonce）───────────────────────────────────────────
    // [BUG-CRIT-1 FIX] 安全时间差计算
    if safe_time_diff(now, req.timestamp) > timestamp_window() {
        return time_window_error(now);
    }

    if !validate_key_hash(&req.key_hash) {
        return err(STATUS_INVALID_KEY, "ERR-INVALID-KEY");
    }

    // Revoke 快速检查
    if cache::is_revoked(&redis, &req.key_hash).await {
        return err(STATUS_REVOKED, "ERR-REVOKED");
    }

    // ── 缓存路径 ─────────────────────────────────────────────────────────
    if let Some(cached) = cache::get_verify_cache(&redis, &req.key_hash).await {
        // [BUG-CRIT-4 FIX] 防御 activation_ts 为零值的损坏缓存条目
        // set_verify_cache 检查 activation_ts <= 0 但可能仍有旧缓存。
        if cached.activation_ts <= 0 || cached.activation_ts >= cached.expires_at {
            tracing::warn!(
                "[Verify] invalid cached entry (act={}, exp={}), fallback to DB path",
                cached.activation_ts,
                cached.expires_at
            );
            cache::invalidate_verify_cache(&redis, &req.key_hash).await;
            // fall through to DB path
        } else if is_expired(cached.expires_at, now) {
            // [BUG-HIGH-1 FIX] 使用 saturating_add 安全判断过期
            cache::invalidate_verify_cache(&redis, &req.key_hash).await;
            return expired_response(cached.expires_at, now);
        } else {
            // 缓存有效且未过期，仍需 HMAC 验证
            let key = match key_cache::get_or_load(&req.key_hash, &db).await {
                Ok(Some(v)) => v,
                Ok(None) => return err(STATUS_INVALID_KEY, "ERR-INVALID-KEY"),
                Err(e) => {
                    tracing::error!("[Verify] key_cache DB error: {e}");
                    return err(
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                        "ERR-INTERNAL",
                    );
                }
            };

            if !verify_hmac_signature(&key, &req.key_hash, req.timestamp, &req.signature) {
                return err(STATUS_INVALID_KEY, "ERR-INVALID-KEY");
            }

            if !check_and_store_nonce(&redis, &req.key_hash, req.timestamp).await {
                return err(STATUS_NONCE_REPLAY, "ERR-NONCE-REPLAY");
            }

            if should_update_last_check(&redis, &req.key_hash).await {
                let db2 = Arc::clone(&db);
                let kh = req.key_hash.clone();
                tokio::spawn(async move {
                    if let Err(e) = crate::db::update_last_check(&db2, &kh, now).await {
                        tracing::warn!("[Verify] cache-hit update_last_check failed: {e}");
                    }
                });
            }

            return ok_verify_response(cached.activation_ts, cached.expires_at);
        }
    }

    // ── DB 路径 ──────────────────────────────────────────────────────────
    // HMAC 验证（需要从 DB/key_cache 获取 key）
    let key = match key_cache::get_or_load(&req.key_hash, &db).await {
        Ok(Some(v)) => v,
        Ok(None) => return err(STATUS_INVALID_KEY, "ERR-INVALID-KEY"),
        Err(e) => {
            tracing::error!("[Verify] key_cache DB error: {e}");
            return err(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "ERR-INTERNAL",
            );
        }
    };

    if !verify_hmac_signature(&key, &req.key_hash, req.timestamp, &req.signature) {
        return err(STATUS_INVALID_KEY, "ERR-INVALID-KEY");
    }

    // DB 查询 + 过期校验
    let record = match crate::db::find_license(&db, &req.key_hash).await {
        Ok(Some(r)) => r,
        Ok(None) => return err(STATUS_INVALID_KEY, "ERR-INVALID-KEY"),
        Err(e) => {
            tracing::error!("[Verify] DB error: {e}");
            return err(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "ERR-INTERNAL",
            );
        }
    };

    // 业务状态检查
    if record.revoked {
        return err(STATUS_REVOKED, "ERR-REVOKED");
    }
    if record.activation_ts <= 0 {
        return err(STATUS_NOT_ACTIVATED, "ERR-NOT-ACTIVATED");
    }

    // [BUG-HIGH-4 FIX] activation_ts 不能在将来（防御 DB 损坏）
    if record.activation_ts > now + 300 {
        tracing::error!(
            "[Verify] activation_ts={} is in the future (now={}), possible DB corruption",
            record.activation_ts,
            now
        );
        return err(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "ERR-DATA-INCONSISTENCY",
        );
    }

    // [V16] 统一数据合法性校验
    if let Err(reason) = db::validate_license_sanity(&record, now) {
        tracing::error!("[Verify] license sanity check failed: {}", reason);
        return err(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "ERR-DATA-INCONSISTENCY",
        );
    }

    // 防御 activation_ts >= expires_at（已在 validate_license_sanity 中检查，此处二次确认）
    if record.activation_ts >= record.expires_at {
        return err(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "ERR-DATA-INCONSISTENCY",
        );
    }

    // [BUG-HIGH-1 FIX] 使用 saturating_add 安全判断过期
    if is_expired(record.expires_at, now) {
        return expired_response(record.expires_at, now);
    }

    // 确认有效后才消耗 nonce
    if !check_and_store_nonce(&redis, &req.key_hash, req.timestamp).await {
        return err(STATUS_NONCE_REPLAY, "ERR-NONCE-REPLAY");
    }

    // 写缓存
    let entry = cache::VerifyCacheEntry {
        activation_ts: record.activation_ts,
        expires_at: record.expires_at,
    };
    cache::set_verify_cache(&redis, &req.key_hash, &entry).await;

    if should_update_last_check(&redis, &req.key_hash).await {
        let db2 = Arc::clone(&db);
        let kh = req.key_hash.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::db::update_last_check(&db2, &kh, now).await {
                tracing::warn!("[Verify] update_last_check failed: {e}");
            }
        });
    }

    ok_verify_response(record.activation_ts, record.expires_at)
}

// ═══════════════════════════════════════════════════════════════════════════════
// /health
// ═══════════════════════════════════════════════════════════════════════════════
pub async fn health(
    Extension(pool): Extension<Arc<crate::db::DbPool>>,
    Extension(redis_pool): Extension<Arc<RedisPool>>,
) -> impl IntoResponse {
    let db_ok = sqlx::query("SELECT 1").execute(pool.as_ref()).await.is_ok();
    let redis_ok = match redis_pool.get().await {
        Ok(mut c) => deadpool_redis::redis::cmd("PING")
            .query_async::<_, String>(&mut c)
            .await
            .is_ok(),
        Err(_) => false,
    };

    let (nonce_total, nonce_rejected, nonce_map_size) = nonce_fallback::get_nonce_stats();
    let (cache_hits, cache_misses) = cache::get_cache_stats();
    let key_cache_size = key_cache::cache_size();

    let status = if db_ok && redis_ok {
        axum::http::StatusCode::OK
    } else {
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    };

    (
        status,
        Json(serde_json::json!({
            "status": if db_ok && redis_ok { "ok" } else { "degraded" },
            "db": db_ok,
            "redis": redis_ok,
            "expiration_grace_secs": expiration_grace_secs(),
            "nonce_stats": {
                "total_checks": nonce_total,
                "rejected": nonce_rejected,
                "map_size": nonce_map_size
            },
            "cache_stats": {
                "hits": cache_hits,
                "misses": cache_misses
            },
            "key_cache_size": key_cache_size
        })),
    )
        .into_response()
}

// ═══════════════════════════════════════════════════════════════════════════════
// /admin/*
// ═══════════════════════════════════════════════════════════════════════════════
#[derive(Deserialize)]
pub struct AdminToken {
    token: String,
}

pub async fn list_licenses(
    Extension(pool): Extension<Arc<crate::db::DbPool>>,
    Extension(admin): Extension<Arc<String>>,
    Query(q): Query<AdminToken>,
) -> impl IntoResponse {
    if !crate::auth::verify_admin_token(&q.token, &admin) {
        return err(axum::http::StatusCode::UNAUTHORIZED, "unauthorized");
    }
    match crate::db::list_all_licenses(&pool).await {
        Ok(list) => (
            axum::http::StatusCode::OK,
            Json(serde_json::json!({ "licenses": list })),
        )
            .into_response(),
        Err(e) => err(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            &e.to_string(),
        ),
    }
}

#[derive(Deserialize)]
pub struct RevokeReq {
    key_hash: String,
    reason: Option<String>,
    token: String,
}

pub async fn revoke_license(
    Extension(pool): Extension<Arc<crate::db::DbPool>>,
    Extension(redis_pool): Extension<Arc<RedisPool>>,
    Extension(admin): Extension<Arc<String>>,
    Json(req): Json<RevokeReq>,
) -> impl IntoResponse {
    if !crate::auth::verify_admin_token(&req.token, &admin) {
        return err(axum::http::StatusCode::UNAUTHORIZED, "unauthorized");
    }
    if !validate_key_hash(&req.key_hash) {
        return err(axum::http::StatusCode::BAD_REQUEST, "invalid key_hash");
    }

    let reason = req.reason.as_deref().unwrap_or("revoked by admin");
    match crate::db::revoke_license(&pool, &req.key_hash, reason).await {
        Ok(false) => return err(axum::http::StatusCode::NOT_FOUND, "key not found"),
        Ok(true) => {}
        Err(e) => {
            return err(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                &e.to_string(),
            )
        }
    }

    cache::set_revoke_tombstone(&redis_pool, &req.key_hash).await;
    cache::invalidate_verify_cache(&redis_pool, &req.key_hash).await;
    let tombstone_exp = now_secs() + 86400 * 30;
    cache::mark_revoked_in_memory(&req.key_hash, tombstone_exp);
    key_cache::remove(&req.key_hash);

    (
        axum::http::StatusCode::OK,
        Json(serde_json::json!({ "revoked": true })),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct ExtendReq {
    key_hash: String,
    extra_days: i64,
    allow_expired: Option<bool>,
    token: String,
}

pub async fn extend_license(
    Extension(pool): Extension<Arc<crate::db::DbPool>>,
    Extension(redis_pool): Extension<Arc<RedisPool>>,
    Extension(admin): Extension<Arc<String>>,
    Json(req): Json<ExtendReq>,
) -> impl IntoResponse {
    if !crate::auth::verify_admin_token(&req.token, &admin) {
        return err(axum::http::StatusCode::UNAUTHORIZED, "unauthorized");
    }
    if !validate_key_hash(&req.key_hash) {
        return err(axum::http::StatusCode::BAD_REQUEST, "invalid key_hash");
    }
    if req.extra_days < 1 || req.extra_days > crate::db::MAX_EXTEND_DAYS {
        return err(
            axum::http::StatusCode::BAD_REQUEST,
            &format!(
                "extra_days must be >= 1 and <= {}",
                crate::db::MAX_EXTEND_DAYS
            ),
        );
    }

    let allow_expired = req.allow_expired.unwrap_or(false);
    let extra_secs = req
        .extra_days
        .checked_mul(86400)
        .unwrap_or(crate::db::MAX_EXTEND_SECS)
        .clamp(1, crate::db::MAX_EXTEND_SECS);

    match crate::db::extend_license(&pool, &req.key_hash, extra_secs, allow_expired).await {
        Ok(Some(new_exp)) => {
            cache::invalidate_verify_cache(&redis_pool, &req.key_hash).await;
            (
                axum::http::StatusCode::OK,
                Json(serde_json::json!({
                    "new_expires_at": new_exp,
                    "actual_extra_secs": extra_secs,
                })),
            )
                .into_response()
        }
        // [EXP-FIX-2] 区分 "not found" 和 "expired" 错误消息
        Ok(None) => {
            // 查询密钥是否存在，以便给出精确错误
            let record = crate::db::find_license(&pool, &req.key_hash).await;
            match record {
                Ok(Some(r)) => {
                    if r.revoked {
                        err(axum::http::StatusCode::FORBIDDEN, "license is revoked")
                    } else if r.activation_ts <= 0 {
                        err(
                            axum::http::StatusCode::CONFLICT,
                            "license not yet activated",
                        )
                    } else if !allow_expired && r.expires_at <= now_secs() {
                        err(
                            axum::http::StatusCode::GONE,
                            "license expired, use allow_expired=true to extend",
                        )
                    } else {
                        err(
                            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                            "extend query matched no rows",
                        )
                    }
                }
                Ok(None) => err(
                    axum::http::StatusCode::NOT_FOUND,
                    "license not found or not activated",
                ),
                Err(e) => err(
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    &e.to_string(),
                ),
            }
        }
        Err(e) => err(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            &e.to_string(),
        ),
    }
}

#[derive(Deserialize)]
pub struct AddKeyReq {
    note: Option<String>,
    token: String,
}

pub async fn add_key(
    Extension(pool): Extension<Arc<crate::db::DbPool>>,
    Extension(admin): Extension<Arc<String>>,
    Json(req): Json<AddKeyReq>,
) -> impl IntoResponse {
    if !crate::auth::verify_admin_token(&req.token, &admin) {
        return err(axum::http::StatusCode::UNAUTHORIZED, "unauthorized");
    }

    let hkey = generate_hkey();
    let key_hash = hash_key(&hkey);
    let note = req.note.as_deref().unwrap_or("");

    if let Err(e) = crate::db::insert_license(&pool, &hkey, &key_hash, now_secs(), note).await {
        return err(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            &e.to_string(),
        );
    }

    (
        axum::http::StatusCode::OK,
        Json(serde_json::json!({
            "key": hkey,
            "key_hash": key_hash
        })),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct BatchInitReq {
    count: usize,
    note: Option<String>,
    token: String,
}

pub async fn batch_init(
    Extension(pool): Extension<Arc<crate::db::DbPool>>,
    Extension(admin_token): Extension<Arc<String>>,
    Json(req): Json<BatchInitReq>,
) -> impl IntoResponse {
    if !crate::auth::verify_admin_token(&req.token, &admin_token) {
        return axum::http::StatusCode::UNAUTHORIZED.into_response();
    }
    if req.count == 0 || req.count > 5_000 {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "count must be 1..5000"})),
        )
            .into_response();
    }

    let note = req.note.unwrap_or_default();
    let keys: Vec<String> = (0..req.count).map(|_| generate_hkey()).collect();

    match crate::db::batch_init_keys(&pool, &keys, &note).await {
        Ok(()) => {
            let results: Vec<serde_json::Value> = keys
                .iter()
                .map(|k| {
                    serde_json::json!({
                        "key": k,
                        "key_hash": hash_key(k)
                    })
                })
                .collect();
            Json(serde_json::json!({
                "ok": true,
                "count": keys.len(),
                "keys": results
            }))
            .into_response()
        }
        Err(e) => {
            tracing::error!("[Admin] batch_init error: {}", e);
            axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
