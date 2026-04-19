// server/src/handlers.rs — 优化版 v12
//
// 本版修复清单（相对于原 v11）：
//
// [CRIT-1 FIX] activate: 错误码倒置修复 (ERR-NOT-ACTIVATED -> ERR-ALREADY-ACTIVATED)
// [CRIT-1 FIX] activate: HMAC 验证提前到 nonce 之前执行
// [MED-1  FIX] verify: Cache Hit 路径增加 nonce 防重放检查
// [OPT-2  FIX] set_verify_cache 在此处调用前已有双重校验（cache.rs v9 配合）
// [OPT-3  FIX] batch_init: 响应只返回 key_hash，不暴露原始密钥

use crate::cache::{RedisPool, VerifyCacheEntry};
use crate::{auth, cache, db, nonce_fallback};
use axum::{Extension, Json, extract::Query, http::StatusCode, response::IntoResponse};
use hex;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

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

/// OPT-A: 使用 subtle::ConstantTimeEq 防止 timing attack
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
    let expected_bytes = mac.finalize().into_bytes();
    let expected_hex = hex::encode(&expected_bytes);
    if expected_hex.len() != sig.len() {
        return false;
    }
    expected_hex.as_bytes().ct_eq(sig.as_bytes()).into()
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
    std::env::var("TIMESTAMP_WINDOW_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300)
}

fn nonce_ttl() -> i64 {
    timestamp_window() * 2 + 30
}

async fn check_and_store_nonce(redis_pool: &RedisPool, key_hash: &str, sig: &str) -> bool {
    let key = format!("nonce:{}:{}", key_hash, sig);
    match redis_pool.get().await {
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
            tracing::warn!("[Nonce] Redis unavailable ({}), using memory fallback", e);
            nonce_fallback::check_and_store(&key, nonce_ttl() as u64)
        }
    }
}

/// MINOR-B FIX: Redis 不可用时直接更新 DB
async fn should_update_last_check(redis_pool: &RedisPool, key_hash: &str) -> bool {
    let throttle_key = format!("lc:v1:lc_throttle:{}", key_hash);
    let Ok(mut conn) = redis_pool.get().await else {
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

// ── POST /activate ────────────────────────────────────────────────────────────

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
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid key_hash format"})),
        )
            .into_response();
    }

    let now = now_secs();

    // [1] 时间窗口校验
    if (now - req.timestamp).abs() > timestamp_window() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "ERR-TIME-RECORD", "server_time": now})),
        )
            .into_response();
    }

    // [2] 查 DB
    let record = match db::find_license(&pool, &req.key_hash).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({"error": "ERR-INVALID-KEY"})),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("[Activate] DB error: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // [3] revoked 检查（前置，不浪费后续资源）
    if record.revoked {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "ERR-REVOKED"})),
        )
            .into_response();
    }

    // [4] 已激活检查
    // CRIT-1 FIX: 错误码从 ERR-NOT-ACTIVATED 修正为 ERR-ALREADY-ACTIVATED（语义正确）
    if record.activation_ts > 0 {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "ERR-ALREADY-ACTIVATED"})),
        )
            .into_response();
    }

    // [5] CRIT-1 FIX: HMAC 验证提前到 nonce 之前
    // 签名不合法直接拒绝，避免无效请求消耗 nonce 槽位
    if !verify_hmac_signature(&record.key, &req.key_hash, req.timestamp, &req.signature) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "ERR-INVALID-KEY"})),
        )
            .into_response();
    }

    // [6] nonce 防重放（HMAC 验证通过后再检查）
    if !check_and_store_nonce(&redis_pool, &req.key_hash, &req.signature).await {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": "ERR-NONCE-REPLAY"})),
        )
            .into_response();
    }

    // [7] 激活
    let default_duration_secs: i64 = std::env::var("DEFAULT_LICENSE_DURATION_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(365 * 86400);
    let expires_at = now + default_duration_secs;

    match db::activate_license(&pool, &req.key_hash, now, expires_at).await {
        Ok(true) => {
            tracing::info!("[Activate] Key activated: {}...", &req.key_hash[..8]);
            Json(serde_json::json!({
                "activation_ts": now,
                "expires_at": expires_at,
            }))
            .into_response()
        }
        Ok(false) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "ERR-ALREADY-ACTIVATED"})),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("[Activate] DB error: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

// ── POST /verify ──────────────────────────────────────────────────────────────

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
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid key_hash format (expected 64 hex chars)"})),
        )
            .into_response();
    }

    let now = now_secs();

    // [1] 时间窗口
    if (now - req.timestamp).abs() > timestamp_window() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "ERR-TIME-RECORD", "server_time": now})),
        )
            .into_response();
    }

    // [2] CRIT-C: tombstone O(1) 快速拒绝（在 cache 之前）
    if cache::is_revoked(&redis_pool, &req.key_hash).await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "ERR-REVOKED"})),
        )
            .into_response();
    }

    // [3] BUG-1 FIX: Cache hit 重新验证 HMAC + 检查 expires_at
    //     MED-1 FIX: Cache Hit 也必须执行 nonce 检查，防止重放攻击
    if let Some(cached) = cache::get_verify_cache(&redis_pool, &req.key_hash).await {
        if verify_hmac_signature(&cached.key, &req.key_hash, req.timestamp, &req.signature) {
            // MED-1 FIX: cache hit 路径同样需要 nonce 防重放
            if !check_and_store_nonce(&redis_pool, &req.key_hash, &req.signature).await {
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(serde_json::json!({"error": "ERR-NONCE-REPLAY"})),
                )
                    .into_response();
            }

            // CRIT-C FIX: cache hit 再次检查 tombstone（防止 tombstone 写入比 cache 晚）
            if cache::is_revoked(&redis_pool, &req.key_hash).await {
                return (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({"error": "ERR-REVOKED"})),
                )
                    .into_response();
            }

            // 检查缓存中的 expires_at
            if now >= cached.expires_at {
                cache::invalidate_verify_cache(&redis_pool, &req.key_hash).await;
                return (
                    StatusCode::GONE,
                    Json(serde_json::json!({"error": "ERR-EXPIRED", "server_time": now})),
                )
                    .into_response();
            }

            // cache hit 成功
            let update = should_update_last_check(&redis_pool, &req.key_hash).await;
            if update {
                let _ = db::update_last_check(&pool, &req.key_hash, now).await;
            }
            return Json(serde_json::json!({
                "activation_ts": cached.activation_ts,
                "expires_at": cached.expires_at,
                "revoked": false,
            }))
            .into_response();
        }
    }

    // [4] cache miss: nonce 防重放
    if !check_and_store_nonce(&redis_pool, &req.key_hash, &req.signature).await {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": "ERR-NONCE-REPLAY"})),
        )
            .into_response();
    }

    // [5] 查 DB
    let record = match db::find_license(&pool, &req.key_hash).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({"error": "ERR-INVALID-KEY"})),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("[Verify] DB error: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // [6] HMAC 签名验证
    if !verify_hmac_signature(&record.key, &req.key_hash, req.timestamp, &req.signature) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "ERR-INVALID-KEY"})),
        )
            .into_response();
    }

    // [7] revoked
    if record.revoked {
        cache::set_revoked_tombstone(&redis_pool, &req.key_hash).await;
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "ERR-REVOKED"})),
        )
            .into_response();
    }

    // [8] 未激活
    if record.activation_ts <= 0 {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "ERR-NOT-ACTIVATED"})),
        )
            .into_response();
    }

    // [9] BUG-3 FIX: activation_ts >= expires_at 数据异常
    if record.activation_ts >= record.expires_at {
        tracing::error!(
            "[Verify] Data anomaly: activation_ts({}) >= expires_at({}) for key {}...",
            record.activation_ts,
            record.expires_at,
            &req.key_hash[..8]
        );
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "ERR-DATA-ANOMALY"})),
        )
            .into_response();
    }

    // [10] 过期检查
    if now >= record.expires_at {
        let days_expired = (now - record.expires_at) / 86400;
        tracing::info!(
            "[Verify] Key expired {}d ago: {}...",
            days_expired,
            &req.key_hash[..8]
        );
        return (
            StatusCode::GONE,
            Json(serde_json::json!({"error": "ERR-EXPIRED", "server_time": now})),
        )
            .into_response();
    }

    // [11] 写缓存 + 更新 last_check
    let entry = VerifyCacheEntry {
        key: record.key.clone(),
        activation_ts: record.activation_ts,
        expires_at: record.expires_at,
    };
    cache::set_verify_cache(&redis_pool, &req.key_hash, &entry).await;

    let update = should_update_last_check(&redis_pool, &req.key_hash).await;
    if update {
        if let Err(e) = db::update_last_check(&pool, &req.key_hash, now).await {
            tracing::warn!("[Verify] last_check update failed: {}", e);
        }
    }

    tracing::info!("[Verify] OK: {}...", &req.key_hash[..8]);
    Json(serde_json::json!({
        "activation_ts": record.activation_ts,
        "expires_at": record.expires_at,
        "revoked": false,
    }))
    .into_response()
}

// ── GET /health ────────────────────────────────────────────────────────────────

pub async fn health() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "server_id": get_server_id(),
        "version": "v12",
    }))
}

// ── Admin Handlers ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AdminToken {
    token: String,
}

fn check_admin(provided: &str, expected: &Arc<String>) -> bool {
    auth::verify_admin_token(provided, expected)
}

#[derive(Deserialize)]
pub struct ListQuery {
    token: String,
}

pub async fn list_licenses(
    Extension(pool): Extension<Arc<db::DbPool>>,
    Extension(admin_token): Extension<Arc<String>>,
    Query(q): Query<ListQuery>,
) -> impl IntoResponse {
    if !check_admin(&q.token, &admin_token) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match db::list_all_licenses(&pool).await {
        Ok(licenses) => Json(serde_json::json!({"licenses": licenses})).into_response(),
        Err(e) => {
            tracing::error!("[Admin] list_licenses error: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct RevokeReq {
    token: String,
    key_hash: String,
    reason: Option<String>,
}

pub async fn revoke_license(
    Extension(pool): Extension<Arc<db::DbPool>>,
    Extension(redis_pool): Extension<Arc<RedisPool>>,
    Extension(admin_token): Extension<Arc<String>>,
    Json(req): Json<RevokeReq>,
) -> impl IntoResponse {
    if !check_admin(&req.token, &admin_token) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if !validate_key_hash(&req.key_hash) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let reason = req.reason.unwrap_or_else(|| "revoked by admin".to_string());
    match db::revoke_license(&pool, &req.key_hash, &reason).await {
        Ok(()) => {
            cache::set_revoked_tombstone(&redis_pool, &req.key_hash).await;
            cache::invalidate_verify_cache(&redis_pool, &req.key_hash).await;
            tracing::info!("[Admin] Revoked: {}...", &req.key_hash[..8]);
            Json(serde_json::json!({"ok": true})).into_response()
        }
        Err(e) => {
            tracing::error!("[Admin] revoke error: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct ExtendReq {
    token: String,
    key_hash: String,
    extra_days: i64,
}

pub async fn extend_license(
    Extension(pool): Extension<Arc<db::DbPool>>,
    Extension(redis_pool): Extension<Arc<RedisPool>>,
    Extension(admin_token): Extension<Arc<String>>,
    Json(req): Json<ExtendReq>,
) -> impl IntoResponse {
    if !check_admin(&req.token, &admin_token) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    // OPT-4 FIX: 引用 db 层常量（db::MAX_EXTEND_DAYS），消除硬编码重复
    if req.extra_days < 1 || req.extra_days > db::MAX_EXTEND_DAYS {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "extra_days must be 1..=MAX_EXTEND_DAYS"})),
        )
            .into_response();
    }
    let extra_secs = req.extra_days * 86400;
    match db::extend_license(&pool, &req.key_hash, extra_secs).await {
        Ok(Some(new_expires)) => {
            cache::invalidate_verify_cache(&redis_pool, &req.key_hash).await;
            Json(serde_json::json!({"ok": true, "new_expires_at": new_expires})).into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "key not found or not activated"})),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("[Admin] extend error: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct AddKeyReq {
    token: String,
    note: Option<String>,
}

pub async fn add_key(
    Extension(pool): Extension<Arc<db::DbPool>>,
    Extension(admin_token): Extension<Arc<String>>,
    Json(req): Json<AddKeyReq>,
) -> impl IntoResponse {
    if !check_admin(&req.token, &admin_token) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let key = generate_hkey();
    let key_hash = hash_key(&key);
    let now = now_secs();
    let note = req.note.unwrap_or_default();
    match db::insert_license(&pool, &key, &key_hash, now, &note).await {
        Ok(()) => Json(serde_json::json!({
            "key": key,
            "key_hash": key_hash,
        }))
        .into_response(),
        Err(e) => {
            tracing::error!("[Admin] add_key error: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct BatchInitReq {
    token: String,
    count: usize,
    note: Option<String>,
}

pub async fn batch_init(
    Extension(pool): Extension<Arc<db::DbPool>>,
    Extension(admin_token): Extension<Arc<String>>,
    Json(req): Json<BatchInitReq>,
) -> impl IntoResponse {
    if !check_admin(&req.token, &admin_token) {
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
            // OPT-3 FIX: 不暴露原始密钥，只返回 key_hash 列表
            // 原始密钥已安全存储在 DB，通过带外渠道分发
            let key_hashes: Vec<String> = keys.iter().map(|k| hash_key(k)).collect();
            tracing::info!("[Admin] batch_init: {} keys created", keys.len());
            Json(serde_json::json!({
                "ok": true,
                "count": keys.len(),
                "key_hashes": key_hashes,
            }))
            .into_response()
        }
        Err(e) => {
            tracing::error!("[Admin] batch_init error: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
