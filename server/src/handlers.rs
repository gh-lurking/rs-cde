// server/src/handlers.rs — 优化版 v4
//
// 修复列表：
// ✅ BUG-01: DB路径 nonce 消耗移到签名验证之后
// ✅ BUG-02: 缓存命中路径 nonce 消耗移到过期检查之后
// ✅ BUG-03: activate 中 HMAC 提前到所有业务状态判断之前
// ✅ BUG-04: DB路径补充 activation_ts == 0 的未激活检查
// ✅ BUG-06: 节流键通过 cache::throttle_key() 统一管理
// ✅ BUG-11: 缓存签名失败时 invalidate 后 fall-through 到 DB 路径
// ✅ BUG-12: extra_days * 86400 使用 checked_mul 防溢出

use crate::cache::{RedisPool, VerifyCacheEntry};
use crate::{auth, cache, db, nonce_fallback};
use axum::{extract::Query, http::StatusCode, response::IntoResponse, Extension, Json};
use hex;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use uuid::Uuid;

type HmacSha256 = Hmac<sha2::Sha256>;

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
    let expected_hex = hex::encode(mac.finalize().into_bytes());
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
            tracing::warn!("[Nonce] Redis 不可用 ({}), 使用内存降级", e);
            nonce_fallback::check_and_store(&key, nonce_ttl() as u64)
        }
    }
}

async fn should_update_last_check(redis_pool: &RedisPool, key_hash: &str) -> bool {
    // ✅ BUG-06: 使用 cache::throttle_key() 统一命名空间
    let throttle_key = cache::throttle_key(key_hash);
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

// ── POST /activate ─────────────────────────────────────────────────────────

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
            Json(serde_json::json!({"error":"invalid key_hash format"})),
        )
            .into_response();
    }

    let now = now_secs();
    if (now - req.timestamp).abs() > timestamp_window() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error":"ERR-TIME-RECORD","server_time":now})),
        )
            .into_response();
    }

    // 1. 先查 DB（需要 record.key 才能验签）
    let record = match db::find_license(&pool, &req.key_hash).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({"error":"ERR-INVALID-KEY"})),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!("[Activate] DB 查询失败: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // 2. revoked 检查（便宜，纯读）
    if record.revoked {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error":"ERR-REVOKED"})),
        )
            .into_response();
    }

    // ✅ BUG-03 FIX: HMAC 验证提前到所有业务状态判断之前
    if !verify_hmac_signature(&record.key, &req.key_hash, req.timestamp, &req.signature) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error":"ERR-INVALID-KEY"})),
        )
            .into_response();
    }

    // ✅ 签名通过后再消耗 nonce，防止 nonce-DoS
    if !check_and_store_nonce(&redis_pool, &req.key_hash, &req.signature).await {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error":"ERR-NONCE-REPLAY"})),
        )
            .into_response();
    }

    // 业务状态检查（已激活冲突）
    if record.activation_ts > 0 {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error":"ERR-ALREADY-ACTIVATED"})),
        )
            .into_response();
    }

    let default_duration: i64 = std::env::var("DEFAULT_LICENSE_DURATION_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(365 * 86400);
    let expires_at = now + default_duration;

    match db::activate_license(&pool, &req.key_hash, now, expires_at).await {
        Ok(true) => {
            Json(serde_json::json!({"activation_ts":now,"expires_at":expires_at})).into_response()
        }
        Ok(false) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error":"ERR-ALREADY-ACTIVATED"})),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("[Activate] DB 更新失败: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

// ── POST /verify ───────────────────────────────────────────────────────────

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
            Json(serde_json::json!({"error":"invalid key_hash format"})),
        )
            .into_response();
    }

    let now = now_secs();
    if (now - req.timestamp).abs() > timestamp_window() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error":"ERR-TIME-RECORD","server_time":now})),
        )
            .into_response();
    }

    // 快速路径：tombstone 检查（最廉价，纯读）
    if cache::is_revoked(&redis_pool, &req.key_hash).await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error":"ERR-REVOKED"})),
        )
            .into_response();
    }

    // ─── 缓存命中路径 ────────────────────────────────────────────────────
    if let Some(cached) = cache::get_verify_cache(&redis_pool, &req.key_hash).await {
        let cached_key_hash = hash_key(&cached.key);
        if cached_key_hash != req.key_hash {
            // 缓存污染：清除后 fall-through 到 DB 路径
            cache::invalidate_verify_cache(&redis_pool, &req.key_hash).await;
        } else if verify_hmac_signature(&cached.key, &req.key_hash, req.timestamp, &req.signature) {
            // ✅ 签名正确

            // ✅ BUG-02 FIX: 先做只读检查（tombstone + 过期），再消耗 nonce
            // tombstone 再次确认（Redis 可能刚写入）
            if cache::is_revoked(&redis_pool, &req.key_hash).await {
                return (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({"error":"ERR-REVOKED"})),
                )
                    .into_response();
            }

            // 过期检查（纯读，无副作用）
            if now >= cached.expires_at {
                cache::invalidate_verify_cache(&redis_pool, &req.key_hash).await;
                return (
                    StatusCode::GONE,
                    Json(serde_json::json!({"error":"ERR-EXPIRED","server_time":now})),
                )
                    .into_response();
            }

            // ✅ 最后消耗 nonce（有写副作用，确认无误后执行）
            if !check_and_store_nonce(&redis_pool, &req.key_hash, &req.signature).await {
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(serde_json::json!({"error":"ERR-NONCE-REPLAY"})),
                )
                    .into_response();
            }

            if should_update_last_check(&redis_pool, &req.key_hash).await {
                let _ = db::update_last_check(&pool, &req.key_hash, now).await;
            }

            return Json(serde_json::json!({
                "activation_ts": cached.activation_ts,
                "expires_at": cached.expires_at,
                "revoked": false,
            }))
            .into_response();
        } else {
            // ✅ BUG-11 FIX: 签名失败时 invalidate 缓存，fall-through 到 DB 路径
            // 处理 server_id 变更等配置变更场景，而非立即 403
            tracing::warn!(
                "[Verify] 缓存签名不匹配 {}..., 使缓存失效并重新验证",
                &req.key_hash[..8]
            );
            cache::invalidate_verify_cache(&redis_pool, &req.key_hash).await;
            // fall-through to DB path
        }
    }

    // ─── 缓存未命中 / 缓存污染后的 DB 路径 ──────────────────────────────

    // ✅ BUG-01 FIX: 先查 DB + 验签，再消耗 nonce
    let record = match db::find_license(&pool, &req.key_hash).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({"error":"ERR-INVALID-KEY"})),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!("[Verify] DB: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // HMAC 验签（依赖 record.key，必须在 DB 查询之后）
    if !verify_hmac_signature(&record.key, &req.key_hash, req.timestamp, &req.signature) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error":"ERR-INVALID-KEY"})),
        )
            .into_response();
    }

    // ✅ 签名通过后再消耗 nonce（防止签名失败时 nonce 被占用造成合法用户 DoS）
    if !check_and_store_nonce(&redis_pool, &req.key_hash, &req.signature).await {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error":"ERR-NONCE-REPLAY"})),
        )
            .into_response();
    }

    if record.revoked {
        cache::set_revoked_tombstone(&redis_pool, &req.key_hash).await;
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error":"ERR-REVOKED"})),
        )
            .into_response();
    }

    // ✅ BUG-04 FIX: 补充 activation_ts == 0 的未激活检查
    if record.activation_ts == 0 {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error":"ERR-NOT-ACTIVATED"})),
        )
            .into_response();
    }

    if record.activation_ts >= record.expires_at {
        tracing::error!(
            "[Verify] 数据异常: activation_ts({}) >= expires_at({})",
            record.activation_ts,
            record.expires_at
        );
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error":"ERR-DATA-ANOMALY"})),
        )
            .into_response();
    }

    if now >= record.expires_at {
        return (
            StatusCode::GONE,
            Json(serde_json::json!({"error":"ERR-EXPIRED","server_time":now})),
        )
            .into_response();
    }

    let entry = VerifyCacheEntry {
        key: record.key.clone(),
        activation_ts: record.activation_ts,
        expires_at: record.expires_at,
    };
    cache::set_verify_cache(&redis_pool, &req.key_hash, &entry).await;

    if should_update_last_check(&redis_pool, &req.key_hash).await {
        if let Err(e) = db::update_last_check(&pool, &req.key_hash, now).await {
            tracing::warn!("[Verify] last_check 更新失败: {}", e);
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

// ── GET /health ────────────────────────────────────────────────────────────

pub async fn health() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "server_id": get_server_id(),
        "version": "v4",
    }))
}

// ── Admin: list_licenses ───────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ListQuery {
    token: String,
}

pub async fn list_licenses(
    Extension(pool): Extension<Arc<db::DbPool>>,
    Extension(admin_token): Extension<Arc<String>>,
    Query(q): Query<ListQuery>,
) -> impl IntoResponse {
    if !auth::verify_admin_token(&q.token, &admin_token) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match db::list_all_licenses(&pool).await {
        Ok(ls) => Json(serde_json::json!({"licenses": ls})).into_response(),
        Err(e) => {
            tracing::error!("[Admin] list: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

// ── Admin: revoke_license ──────────────────────────────────────────────────

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
    if !auth::verify_admin_token(&req.token, &admin_token) {
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
            tracing::info!("[Admin] 已撤销: {}...", &req.key_hash[..8]);
            Json(serde_json::json!({"ok": true})).into_response()
        }
        Err(e) => {
            tracing::error!("[Admin] revoke: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

// ── Admin: extend_license ──────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ExtendReq {
    token: String,
    key_hash: String,
    extra_days: i64,
    allow_expired: Option<bool>,
}

pub async fn extend_license(
    Extension(pool): Extension<Arc<db::DbPool>>,
    Extension(redis_pool): Extension<Arc<RedisPool>>,
    Extension(admin_token): Extension<Arc<String>>,
    Json(req): Json<ExtendReq>,
) -> impl IntoResponse {
    if !auth::verify_admin_token(&req.token, &admin_token) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    // ✅ BUG-12 FIX: 使用 checked_mul 防止 extra_days * 86400 溢出
    let extra_secs = match req.extra_days.checked_mul(86400) {
        Some(s) if s > 0 && s <= db::MAX_EXTEND_SECS => s,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error":"extra_days out of range"})),
            )
                .into_response();
        }
    };

    let allow_expired = req.allow_expired.unwrap_or(false);
    match db::extend_license(&pool, &req.key_hash, extra_secs, allow_expired).await {
        Ok(Some(new_exp)) => {
            cache::invalidate_verify_cache(&redis_pool, &req.key_hash).await;
            Json(serde_json::json!({"ok":true,"new_expires_at":new_exp})).into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error":"key not found or already expired"})),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("[Admin] extend: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

// ── Admin: add_key ─────────────────────────────────────────────────────────

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
    if !auth::verify_admin_token(&req.token, &admin_token) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let key = generate_hkey();
    let key_hash = hash_key(&key);
    let note = req.note.unwrap_or_default();
    match db::insert_license(&pool, &key, &key_hash, now_secs(), &note).await {
        Ok(()) => Json(serde_json::json!({"key": key, "key_hash": key_hash})).into_response(),
        Err(e) => {
            tracing::error!("[Admin] add_key: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

// ── Admin: batch_init ──────────────────────────────────────────────────────

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
    if !auth::verify_admin_token(&req.token, &admin_token) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if req.count == 0 || req.count > 10_000 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error":"count must be 1..10000"})),
        )
            .into_response();
    }
    let note = req.note.unwrap_or_default();
    let (keys, key_hashes): (Vec<String>, Vec<String>) = (0..req.count)
        .map(|_| {
            let k = generate_hkey();
            let h = hash_key(&k);
            (k, h)
        })
        .unzip();

    match db::batch_init_keys(&pool, &keys, &key_hashes, &note).await {
        Ok(()) => {
            let results: Vec<_> = keys
                .iter()
                .zip(key_hashes.iter())
                .map(|(k, h)| serde_json::json!({"key": k, "key_hash": h}))
                .collect();
            tracing::info!("[Admin] batch_init: {} 个 key", keys.len());
            Json(serde_json::json!({
                "ok": true,
                "count": keys.len(),
                "keys": results
            }))
            .into_response()
        }
        Err(e) => {
            tracing::error!("[Admin] batch_init: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
