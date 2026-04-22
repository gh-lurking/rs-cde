// server/src/handlers.rs — 优化版 v7
//
// [BUG-A2 FIX] 缓存命中路径强制 revoke 二次检查（解决 revoke→invalidate 竞态窗口）
// [BUG-A3 FIX] 统一 HTTP 状态码常量，消除散落的魔法数字
// [BUG-A4 FIX] revoke handler 同时写 Redis tombstone（重启后持久有效）
// [BUG-A8 FIX] 缓存命中响应补充 revoked: false 字段（与 DB 路径响应对称）
// [BUG-A10 FIX] nonce key 改为 {key_hash}:{timestamp}，避免未验证 sig 注入 Redis

use crate::cache::{RedisPool, VerifyCacheEntry};
use crate::{auth, cache, db, nonce_fallback};
use axum::{extract::Query, http::StatusCode, response::IntoResponse, Extension, Json};
use hex;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use serde::Deserialize;
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use uuid::Uuid;

type HmacSha256 = Hmac<sha2::Sha256>;

// [BUG-A3 FIX] 统一状态码常量
const STATUS_EXPIRED: StatusCode = StatusCode::GONE;
const STATUS_REVOKED: StatusCode = StatusCode::FORBIDDEN;
const STATUS_NOT_ACTIVATED: StatusCode = StatusCode::CONFLICT;
const STATUS_NONCE_REPLAY: StatusCode = StatusCode::CONFLICT;
const STATUS_INVALID_KEY: StatusCode = StatusCode::FORBIDDEN;

static SERVER_ID: OnceLock<String> = OnceLock::new();
fn get_server_id() -> &'static str {
    SERVER_ID.get_or_init(|| {
        std::env::var("SERVER_ID").unwrap_or_else(|_| "license-server-v1".to_string())
    })
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn hash_key(key: &str) -> String {
    let mut h = Sha256::new();
    h.update(key.as_bytes());
    hex::encode(h.finalize())
}

fn validate_key_hash(key_hash: &str) -> bool {
    key_hash.len() == 64 && key_hash.chars().all(|c| c.is_ascii_hexdigit())
}

fn verify_hmac_signature(key: &str, key_hash: &str, timestamp: i64, sig: &str) -> bool {
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

// [BUG-A10 FIX] nonce key 只用 key_hash + timestamp（不含未验证的 sig）
// timestamp 在时间窗口 300s 内，每个 key 最多 ~300 个不同 nonce，防止 Redis 膨胀
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
            tracing::warn!("[Nonce] Redis 不可用 ({}), 使用内存 fallback", e);
            nonce_fallback::check_and_store(&key, nonce_ttl() as u64)
        }
    }
}

async fn should_update_last_check(pool: &RedisPool, key_hash: &str) -> bool {
    let throttle_key = cache::throttle_key(key_hash);
    let Ok(mut conn) = pool.get().await else {
        return true;
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

// 统一成功响应构造
fn ok_verify_response(activation_ts: i64, expires_at: i64) -> axum::response::Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "activation_ts": activation_ts,
            "expires_at": expires_at,
            "revoked": false,   // [BUG-A8 FIX] 统一包含 revoked 字段
        })),
    )
        .into_response()
}

// ═══════════════════════════════════════════════════════
// POST /activate
// ═══════════════════════════════════════════════════════
#[derive(Deserialize)]
pub struct ActivateReq {
    key_hash: String,
    timestamp: i64,
    signature: String,
}

pub async fn activate(
    Extension(pool): Extension<Arc<db::DbPool>>,
    Extension(redis_pool): Extension<Arc<RedisPool>>,
    Json(req): Json<ActivateReq>,
) -> impl IntoResponse {
    if !validate_key_hash(&req.key_hash) {
        return err(StatusCode::BAD_REQUEST, "invalid key_hash format");
    }
    let now = now_secs();
    if (now - req.timestamp).abs() > timestamp_window() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "ERR-TIME-RECORD", "server_time": now })),
        )
            .into_response();
    }
    let record = match db::find_license(&pool, &req.key_hash).await {
        Ok(Some(r)) => r,
        Ok(None) => return err(STATUS_INVALID_KEY, "ERR-INVALID-KEY"),
        Err(e) => {
            tracing::error!("[Activate] DB error: {}", e);
            return err(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
        }
    };
    if record.revoked {
        return err(STATUS_REVOKED, "ERR-REVOKED");
    }
    if record.activation_ts > 0 {
        return err(STATUS_NOT_ACTIVATED, "ERR-ALREADY-ACTIVATED");
    }
    // [BUG-A10 FIX] nonce 检查用 timestamp，不含未验证的 sig
    if !check_and_store_nonce(&redis_pool, &req.key_hash, req.timestamp).await {
        return err(STATUS_NONCE_REPLAY, "ERR-NONCE-REPLAY");
    }
    if !verify_hmac_signature(&record.key, &req.key_hash, req.timestamp, &req.signature) {
        return err(STATUS_INVALID_KEY, "ERR-INVALID-KEY");
    }
    let activation_ts = now;
    let default_days: i64 = std::env::var("DEFAULT_LICENSE_DAYS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(365);
    let extra_secs = default_days
        .checked_mul(86400)
        .unwrap_or(db::MAX_EXTEND_SECS)
        .clamp(1, db::MAX_EXTEND_SECS);
    let expires_at = activation_ts + extra_secs;

    match db::activate_license(&pool, &req.key_hash, activation_ts, expires_at).await {
        Ok(true) => {
            tracing::info!("[Activate] activated key_hash={}...", &req.key_hash[..8]);
            ok_verify_response(activation_ts, expires_at)
        }
        Ok(false) => {
            tracing::warn!(
                "[Activate] concurrent activation for {}...",
                &req.key_hash[..8]
            );
            err(STATUS_NOT_ACTIVATED, "ERR-ALREADY-ACTIVATED")
        }
        Err(e) => {
            tracing::error!("[Activate] DB write: {}", e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
        }
    }
}

// ═══════════════════════════════════════════════════════
// POST /verify
// ═══════════════════════════════════════════════════════
#[derive(Deserialize)]
pub struct VerifyReq {
    key_hash: String,
    timestamp: i64,
    signature: String,
}

pub async fn verify(
    Extension(pool): Extension<Arc<db::DbPool>>,
    Extension(redis_pool): Extension<Arc<RedisPool>>,
    Json(req): Json<VerifyReq>,
) -> impl IntoResponse {
    if !validate_key_hash(&req.key_hash) {
        return err(StatusCode::BAD_REQUEST, "invalid key_hash format");
    }
    let now = now_secs();
    if (now - req.timestamp).abs() > timestamp_window() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "ERR-TIME-RECORD", "server_time": now })),
        )
            .into_response();
    }

    // 快速 revoke 检查（内存 map → Redis tombstone）
    if cache::is_revoked(&redis_pool, &req.key_hash).await {
        return err(STATUS_REVOKED, "ERR-REVOKED");
    }

    // 缓存命中路径
    if let Some(entry) = cache::get_verify_cache(&redis_pool, &req.key_hash).await {
        // [BUG-A2 FIX] 缓存命中后强制二次 revoke 检查（解决 revoke→invalidate 竞态）
        if cache::is_revoked(&redis_pool, &req.key_hash).await {
            cache::invalidate_verify_cache(&redis_pool, &req.key_hash).await;
            return err(STATUS_REVOKED, "ERR-REVOKED");
        }
        // [BUG-A10 FIX] nonce 用 timestamp
        if !check_and_store_nonce(&redis_pool, &req.key_hash, req.timestamp).await {
            return err(STATUS_NONCE_REPLAY, "ERR-NONCE-REPLAY");
        }
        if !verify_hmac_signature(&entry.key, &req.key_hash, req.timestamp, &req.signature) {
            return err(STATUS_INVALID_KEY, "ERR-INVALID-KEY");
        }
        // [BUG-A2 FIX] 对称的完整校验
        if entry.activation_ts <= 0 {
            return err(STATUS_NOT_ACTIVATED, "ERR-NOT-ACTIVATED");
        }
        if entry.expires_at <= now {
            cache::invalidate_verify_cache(&redis_pool, &req.key_hash).await;
            return err(STATUS_EXPIRED, "ERR-EXPIRED");
        }
        // [BUG-A8 FIX] 统一响应结构（含 revoked: false）
        return ok_verify_response(entry.activation_ts, entry.expires_at);
    }

    // DB 路径
    let record = match db::find_license(&pool, &req.key_hash).await {
        Ok(Some(r)) => r,
        Ok(None) => return err(STATUS_INVALID_KEY, "ERR-INVALID-KEY"),
        Err(e) => {
            tracing::error!("[Verify] DB error: {}", e);
            return err(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
        }
    };
    if record.revoked {
        cache::mark_revoked_in_memory(&req.key_hash, record.expires_at);
        return err(STATUS_REVOKED, "ERR-REVOKED");
    }
    if record.activation_ts == 0 {
        return err(STATUS_NOT_ACTIVATED, "ERR-NOT-ACTIVATED");
    }
    // [BUG-A10 FIX] nonce 用 timestamp
    if !check_and_store_nonce(&redis_pool, &req.key_hash, req.timestamp).await {
        return err(STATUS_NONCE_REPLAY, "ERR-NONCE-REPLAY");
    }
    if !verify_hmac_signature(&record.key, &req.key_hash, req.timestamp, &req.signature) {
        return err(STATUS_INVALID_KEY, "ERR-INVALID-KEY");
    }
    if record.expires_at <= now {
        return err(STATUS_EXPIRED, "ERR-EXPIRED");
    }

    // 写缓存
    cache::set_verify_cache(
        &redis_pool,
        &req.key_hash,
        &VerifyCacheEntry {
            key: record.key.clone(),
            activation_ts: record.activation_ts,
            expires_at: record.expires_at,
        },
    )
    .await;

    if should_update_last_check(&redis_pool, &req.key_hash).await {
        let _ = db::update_last_check(&pool, &req.key_hash, now).await;
    }

    ok_verify_response(record.activation_ts, record.expires_at)
}

pub async fn health(Extension(redis_pool): Extension<Arc<RedisPool>>) -> impl IntoResponse {
    let (nonce_total, nonce_rejected, nonce_map_size) = nonce_fallback::get_nonce_stats();
    let (cache_hits, cache_misses) = cache::get_cache_stats();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "ok",
            "nonce_stats": {
                "total_checks": nonce_total,
                "rejected": nonce_rejected,
                "map_size": nonce_map_size
            },
            "cache_stats": {
                "hits": cache_hits,
                "misses": cache_misses,
            }
        })),
    )
        .into_response()
}

fn err(code: StatusCode, msg: &str) -> axum::response::Response {
    (code, Json(serde_json::json!({ "error": msg }))).into_response()
}

// ═══════════════════════════════════════════════════════
// Admin endpoints
// ═══════════════════════════════════════════════════════
#[derive(Deserialize)]
pub struct AdminToken {
    token: String,
}

pub async fn list_licenses(
    Extension(pool): Extension<Arc<db::DbPool>>,
    Extension(admin): Extension<Arc<String>>,
    Query(q): Query<AdminToken>,
) -> impl IntoResponse {
    if !auth::verify_admin_token(&q.token, &admin) {
        return err(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    match db::list_all_licenses(&pool).await {
        Ok(list) => (
            StatusCode::OK,
            Json(serde_json::json!({ "licenses": list })),
        )
            .into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

#[derive(Deserialize)]
pub struct RevokeReq {
    key_hash: String,
    reason: Option<String>,
    token: String,
}

pub async fn revoke_license(
    Extension(pool): Extension<Arc<db::DbPool>>,
    Extension(redis_pool): Extension<Arc<RedisPool>>,
    Extension(admin): Extension<Arc<String>>,
    Json(req): Json<RevokeReq>,
) -> impl IntoResponse {
    if !auth::verify_admin_token(&req.token, &admin) {
        return err(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    if !validate_key_hash(&req.key_hash) {
        return err(StatusCode::BAD_REQUEST, "invalid key_hash");
    }
    let reason = req.reason.as_deref().unwrap_or("revoked by admin");
    if let Err(e) = db::revoke_license(&pool, &req.key_hash, reason).await {
        return err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string());
    }
    cache::invalidate_verify_cache(&redis_pool, &req.key_hash).await;
    // [BUG-A4 FIX] 同时写 Redis tombstone（重启后持久有效）
    cache::set_revoke_tombstone(&redis_pool, &req.key_hash).await;
    // 写内存 map（加速本实例检查）
    let tombstone_exp = now_secs() + 86400 * 30;
    cache::mark_revoked_in_memory(&req.key_hash, tombstone_exp);
    (StatusCode::OK, Json(serde_json::json!({ "revoked": true }))).into_response()
}

#[derive(Deserialize)]
pub struct ExtendReq {
    key_hash: String,
    extra_days: i64,
    allow_expired: Option<bool>,
    token: String,
}

pub async fn extend_license(
    Extension(pool): Extension<Arc<db::DbPool>>,
    Extension(redis_pool): Extension<Arc<RedisPool>>,
    Extension(admin): Extension<Arc<String>>,
    Json(req): Json<ExtendReq>,
) -> impl IntoResponse {
    if !auth::verify_admin_token(&req.token, &admin) {
        return err(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    if !validate_key_hash(&req.key_hash) {
        return err(StatusCode::BAD_REQUEST, "invalid key_hash");
    }
    let extra_secs = match req.extra_days.checked_mul(86400) {
        Some(s) => s,
        None => return err(StatusCode::BAD_REQUEST, "extra_days out of range"),
    };
    match db::extend_license(
        &pool,
        &req.key_hash,
        extra_secs,
        req.allow_expired.unwrap_or(false),
    )
    .await
    {
        Ok(Some(new_exp)) => {
            cache::invalidate_verify_cache(&redis_pool, &req.key_hash).await;
            (
                StatusCode::OK,
                Json(serde_json::json!({ "new_expires_at": new_exp })),
            )
                .into_response()
        }
        Ok(None) => err(StatusCode::NOT_FOUND, "license not found or not activated"),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

#[derive(Deserialize)]
pub struct AddKeyReq {
    note: Option<String>,
    token: String,
}

pub async fn add_key(
    Extension(pool): Extension<Arc<db::DbPool>>,
    Extension(admin): Extension<Arc<String>>,
    Json(req): Json<AddKeyReq>,
) -> impl IntoResponse {
    if !auth::verify_admin_token(&req.token, &admin) {
        return err(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    let hkey = generate_hkey();
    let key_hash = hash_key(&hkey);
    let note = req.note.as_deref().unwrap_or("");
    if let Err(e) = db::insert_license(&pool, &hkey, &key_hash, now_secs(), note).await {
        return err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string());
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({ "key": hkey, "key_hash": key_hash })),
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
    Extension(pool): Extension<Arc<db::DbPool>>,
    Extension(admin_token): Extension<Arc<String>>,
    Json(req): Json<BatchInitReq>,
) -> impl IntoResponse {
    if !auth::verify_admin_token(&req.token, &admin_token) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if req.count == 0 || req.count > 10_000 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "count must be 1..10000"})),
        )
            .into_response();
    }
    let note = req.note.unwrap_or_default();
    let keys: Vec<String> = (0..req.count).map(|_| generate_hkey()).collect();
    match db::batch_init_keys(&pool, &keys, &note).await {
        Ok(()) => {
            let results: Vec<serde_json::Value> = keys
                .iter()
                .map(|k| serde_json::json!({ "key": k, "key_hash": hash_key(k) }))
                .collect();
            tracing::info!("[Admin] batch_init: {} keys created", keys.len());
            Json(serde_json::json!({ "ok": true, "count": keys.len(), "keys": results }))
                .into_response()
        }
        Err(e) => {
            tracing::error!("[Admin] batch_init error: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
