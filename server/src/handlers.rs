// server/src/handlers.rs — 优化版 v9
// 修复汇总（相对于 v8）:
// ✅ CRIT-A  FIX: cache hit 分支 activation_ts/expires_at <= 0 校验独立，不与过期检查混合
// ✅ MAJOR-A FIX: DB 回源段 revoked 检查移到 nonce 防重放之前
// ✅ MAJOR-C FIX: activate 接口 nonce 防重放前置（DB find 之前）
// ✅ MINOR-A FIX: get_server_id() 默认值与客户端一致（"license-server-v1"）
// ✅ MINOR-B FIX: should_update_last_check() Redis 故障时返回 false，不放大 DB 压力
// ✅ CRIT-C  FIX: add_key/batch_init 增加 expires_at <= now 校验
// ✅ OPT-A   FIX: verify_hmac_signature 使用 subtle::ConstantTimeEq

use crate::{auth, cache, db, nonce_fallback};
use axum::{
    extract::{Extension, Json, Query},
    http::StatusCode,
    response::IntoResponse,
};
use cache::{RedisPool, VerifyCacheEntry};
use db::DbPool;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use uuid::Uuid;

// ✅ MINOR-A FIX: 默认值与客户端 network.rs 保持一致
static SERVER_ID: OnceLock<String> = OnceLock::new();

fn get_server_id() -> &'static str {
    SERVER_ID.get_or_init(|| {
        std::env::var("SERVER_ID").unwrap_or_else(|_| "license-server-v1".to_string()) // ← 与客户端默认值对齐
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

// ✅ OPT-A FIX: 使用 subtle::ConstantTimeEq，不依赖编译器保证
fn verify_hmac_signature(key: &str, key_hash: &str, timestamp: i64, sig: &str) -> bool {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<sha2::Sha256>;
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
    // 长度不同时，直接 false（HMAC-SHA256 hex 固定 64 字节，长度泄露无意义）
    if expected_hex.len() != sig.len() {
        return false;
    }

    // ✅ subtle 常量时间比较，release 优化安全
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
            tracing::warn!(
                "[Nonce] Redis unavailable ({}), falling back to in-memory nonce (single-node only)",
                e
            );
            nonce_fallback::check_and_store(&key, nonce_ttl() as u64)
        }
    }
}

// ✅ MINOR-B FIX: Redis 故障时返回 false，不放大 DB UPDATE 压力
async fn should_update_last_check(redis_pool: &RedisPool, key_hash: &str) -> bool {
    let throttle_key = format!("lc_throttle:{}", key_hash);
    let Ok(mut conn) = redis_pool.get().await else {
        // Redis 不可用时跳过 last_check 更新，保护 PostgreSQL
        tracing::debug!("[LastCheck] Redis unavailable, skipping last_check update");
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

// ── POST /activate ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ActivateReq {
    key_hash: String,
    timestamp: i64,
    signature: String,
}

pub async fn activate(
    Extension(pool): Extension<Arc<DbPool>>,
    Extension(redis_pool): Extension<Arc<RedisPool>>,
    Json(req): Json<ActivateReq>,
) -> impl IntoResponse {
    if !validate_key_hash(&req.key_hash) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid key_hash format (expected 64 hex chars)"})),
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

    // ✅ MAJOR-C FIX: nonce 防重放提前到 DB 查询之前，减少不必要的 DB 开销
    if !check_and_store_nonce(&redis_pool, &req.key_hash, &req.signature).await {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": "duplicate request (nonce reuse)"})),
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
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };

    // [3] HMAC 验签
    if !verify_hmac_signature(&record.key, &req.key_hash, req.timestamp, &req.signature) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid signature"})),
        )
            .into_response();
    }

    // [4] 业务状态检查
    if record.revoked {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "ERR-REVOKED"})),
        )
            .into_response();
    }

    if record.activation_ts != 0 {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "ERR-ALREADY-ACTIVATED",
                "activation_ts": record.activation_ts,
                "expires_at": record.expires_at

            })),
        )
            .into_response();
    }

    // ✅ CRIT-3 防御：expires_at 必须 > 0
    if record.expires_at <= 0 {
        tracing::error!(
            "[Activate] key_hash={}... expires_at={}, DB data corrupted",
            &req.key_hash[..8.min(req.key_hash.len())],
            record.expires_at
        );

        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "invalid license record: expires_at=0"})),
        )
            .into_response();
    }

    // [5] 执行激活（DB 层 AND activation_ts=0 CAS 防双重激活）
    let activated_ts = now;
    match db::activate_license(&pool, &req.key_hash, activated_ts, record.expires_at).await {
        Ok(true) => {
            tracing::info!(
                "[Activate] key_hash={}... activated, expires_at={}",
                &req.key_hash[..8.min(req.key_hash.len())],
                record.expires_at
            );
            cache::invalidate_verify_cache(&redis_pool, &req.key_hash).await;
            (
                StatusCode::OK,
                Json(serde_json::json!({

                    "activation_ts": activated_ts,

                    "expires_at": record.expires_at,

                })),
            )
                .into_response()
        }
        Ok(false) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "ERR-ALREADY-ACTIVATED"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

// ── POST /verify ───────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct VerifyReq {
    key_hash: String,
    timestamp: i64,
    signature: String,
}

#[derive(Serialize)]
pub struct VerifyResp {
    pub activation_ts: i64,
    pub expires_at: i64,
    pub revoked: bool,
}

pub async fn verify(
    Extension(pool): Extension<Arc<DbPool>>,
    Extension(redis_pool): Extension<Arc<RedisPool>>,
    Json(req): Json<VerifyReq>,
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

    // ── Cache Hit 分支 ─────────────────────────────────────────────────────
    let cache_result = cache::get_verify_cache(&redis_pool, &req.key_hash).await;
    if let Some(cached_entry) = cache_result {
        // Step A: tombstone 优先（revoked=true），无需验签直接拒绝
        if cached_entry.revoked {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({"error": "ERR-REVOKED"})),
            )
                .into_response();
        }

        // Step B: tombstone key 为空串 => 缓存数据异常，回源 DB
        if cached_entry.key.is_empty() {
            tracing::warn!(
                "[Verify] cache entry key is empty but revoked=false, falling back to DB"
            );
            // fall through to DB lookup
        } else {
            // ✅ CRIT-A FIX: activation_ts/expires_at 独立校验（不与过期检查混合）
            // Step C: 数据完整性校验
            if cached_entry.activation_ts <= 0 || cached_entry.expires_at <= 0 {
                tracing::warn!(
                    "[Verify] cache entry has invalid ts (activation={}, expires={}), falling back to DB",
                    cached_entry.activation_ts,
                    cached_entry.expires_at
                );
                // fall through to DB lookup（不能从脏缓存返回）
            } else {
                // Step D: HMAC 验签
                if !verify_hmac_signature(
                    &cached_entry.key,
                    &req.key_hash,
                    req.timestamp,
                    &req.signature,
                ) {
                    return (
                        StatusCode::UNAUTHORIZED,
                        Json(serde_json::json!({"error": "invalid signature"})),
                    )
                        .into_response();
                }

                // Step E: nonce 防重放
                if !check_and_store_nonce(&redis_pool, &req.key_hash, &req.signature).await {
                    return (
                        StatusCode::TOO_MANY_REQUESTS,
                        Json(serde_json::json!({"error": "duplicate request (nonce reuse)"})),
                    )
                        .into_response();
                }

                // Step F: 过期检查（此时 expires_at > 0 已保证）
                if now >= cached_entry.expires_at {
                    let days = (now - cached_entry.expires_at) / 86400;
                    return (
                        StatusCode::GONE,
                        Json(serde_json::json!({"error": "ERR-EXPIRED", "expired_days": days})),
                    )
                        .into_response();
                }

                // ✅ Cache hit 合法：异步更新 last_check
                if should_update_last_check(&redis_pool, &req.key_hash).await {
                    let pool_clone = pool.clone();
                    let key_hash = req.key_hash.clone();
                    tokio::spawn(async move {
                        let req_time = now_secs();
                        let _ = db::update_last_check(&pool_clone, &key_hash, req_time).await;
                    });
                }

                return (
                    StatusCode::OK,
                    Json(VerifyResp {
                        activation_ts: cached_entry.activation_ts,
                        expires_at: cached_entry.expires_at,
                        revoked: false,
                    }),
                )
                    .into_response();
            }
        }
    }

    // ── DB 回源 ──────────────────────────────────────────────────────────
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
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };

    // HMAC 验签（回源后用 DB 明文 key）
    if !verify_hmac_signature(&record.key, &req.key_hash, req.timestamp, &req.signature) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid signature"})),
        )
            .into_response();
    }

    // ✅ MAJOR-A FIX: revoked 检查移到 nonce 防重放之前，避免 revoked key 消耗 nonce 空间
    if record.revoked {
        cache::set_revoked_tombstone(&redis_pool, &req.key_hash).await;
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "ERR-REVOKED"})),
        )
            .into_response();
    }

    // nonce 防重放（revoked 检查通过后才消耗 nonce slot）
    if !check_and_store_nonce(&redis_pool, &req.key_hash, &req.signature).await {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": "duplicate request (nonce reuse)"})),
        )
            .into_response();
    }

    // 未激活 / 数据无效检查
    if record.activation_ts <= 0 || record.expires_at <= 0 {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "ERR-NOT-ACTIVATED"})),
        )
            .into_response();
    }

    // 过期检查
    if now >= record.expires_at {
        let days = (now - record.expires_at) / 86400;
        return (
            StatusCode::GONE,
            Json(serde_json::json!({"error": "ERR-EXPIRED", "expired_days": days})),
        )
            .into_response();
    }

    // ✅ 写入缓存（仅写入合法激活记录）
    let entry = VerifyCacheEntry {
        key: record.key.clone(),
        activation_ts: record.activation_ts,
        expires_at: record.expires_at,
        revoked: false,
    };

    cache::set_verify_cache(&redis_pool, &req.key_hash, &entry).await;
    // 异步更新 last_check
    if should_update_last_check(&redis_pool, &req.key_hash).await {
        let pool_clone = pool.clone();
        let key_hash = req.key_hash.clone();
        tokio::spawn(async move {
            let req_time = now_secs();
            let _ = db::update_last_check(&pool_clone, &key_hash, req_time).await;
        });
    }

    (
        StatusCode::OK,
        Json(VerifyResp {
            activation_ts: record.activation_ts,
            expires_at: record.expires_at,
            revoked: false,
        }),
    )
        .into_response()
}

// ── GET /health ────────────────────────────────────────────────────────────
pub async fn health() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({"status": "ok"})))
}

// ── Admin 鉴权 ─────────────────────────────────────────────────────────────
fn require_admin(
    token: &Arc<String>,
    provided: &str,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if !auth::verify_admin_token(provided, token) {
        Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "unauthorized"})),
        ))
    } else {
        Ok(())
    }
}

#[derive(Deserialize)]
pub struct AdminTokenQuery {
    token: String,
}

pub async fn list_licenses(
    Extension(pool): Extension<Arc<DbPool>>,
    Query(q): Query<AdminTokenQuery>,
    Extension(admin_token): Extension<Arc<String>>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&admin_token, &q.token) {
        return e.into_response();
    }

    match db::list_all_licenses(&pool).await {
        Ok(list) => (StatusCode::OK, Json(serde_json::json!({"licenses": list}))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct RevokeReq {
    token: String,
    key_hash: String,
    reason: Option<String>,
}

pub async fn revoke_license(
    Extension(pool): Extension<Arc<DbPool>>,
    Extension(redis_pool): Extension<Arc<RedisPool>>,
    Extension(admin_token): Extension<Arc<String>>,
    Json(req): Json<RevokeReq>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&admin_token, &req.token) {
        return e.into_response();
    }

    if !validate_key_hash(&req.key_hash) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid key_hash"})),
        )
            .into_response();
    }

    let reason = req.reason.as_deref().unwrap_or("admin revoke");
    match db::revoke_license(&pool, &req.key_hash, reason).await {
        Ok(()) => {
            cache::set_revoked_tombstone(&redis_pool, &req.key_hash).await;
            (StatusCode::OK, Json(serde_json::json!({"revoked": true}))).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct ExtendReq {
    token: String,
    key_hash: String,
    extra_days: i64,
}

pub async fn extend_license(
    Extension(pool): Extension<Arc<DbPool>>,
    Extension(redis_pool): Extension<Arc<RedisPool>>,
    Extension(admin_token): Extension<Arc<String>>,
    Json(req): Json<ExtendReq>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&admin_token, &req.token) {
        return e.into_response();
    }

    if !validate_key_hash(&req.key_hash) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid key_hash"})),
        )
            .into_response();
    }

    if req.extra_days < 1 || req.extra_days > 3650 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "extra_days must be 1-3650"})),
        )
            .into_response();
    }

    let extra_secs = req.extra_days * 86400;

    match db::extend_license(&pool, &req.key_hash, extra_secs).await {
        Ok(Some(new_expires_at)) => {
            cache::invalidate_verify_cache(&redis_pool, &req.key_hash).await;
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "extended": true,
                    "new_expires_at": new_expires_at,
                })),
            )
                .into_response()
        }

        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "key not found or not activated or revoked"})),
        )
            .into_response(),

        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct AddKeyReq {
    token: String,
    expires_at: i64,
    note: Option<String>,
}

pub async fn add_key(
    Extension(pool): Extension<Arc<DbPool>>,
    Extension(admin_token): Extension<Arc<String>>,
    Json(req): Json<AddKeyReq>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&admin_token, &req.token) {
        return e.into_response();
    }

    if req.expires_at <= 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "expires_at must be > 0"})),
        )
            .into_response();
    }

    let now = now_secs();
    // ✅ CRIT-C FIX: 不允许创建已过期的密钥
    if req.expires_at <= now {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "expires_at must be in the future",
                "server_time": now
            })),
        )
            .into_response();
    }

    let hkey = generate_hkey();
    let key_hash = hash_key(&hkey);
    let note = req.note.as_deref().unwrap_or("");

    match db::add_key(&pool, &hkey, &key_hash, req.expires_at, note).await {
        Ok(true) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "key":        hkey,
                "key_hash":   key_hash,
                "expires_at": req.expires_at,
            })),
        )
            .into_response(),
        Ok(false) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "key_hash conflict (UUID collision, retry)"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct BatchInitReq {
    token: String,
    count: u32,
    expires_at: i64,
    note: Option<String>,
}

pub async fn batch_init(
    Extension(pool): Extension<Arc<DbPool>>,
    Extension(admin_token): Extension<Arc<String>>,
    Json(req): Json<BatchInitReq>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&admin_token, &req.token) {
        return e.into_response();
    }

    if req.count == 0 || req.count > 1000 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "count must be 1-1000"})),
        )
            .into_response();
    }

    if req.expires_at <= 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "expires_at must be > 0"})),
        )
            .into_response();
    }

    let now = now_secs();
    // ✅ CRIT-C FIX: 不允许批量创建已过期密钥
    if req.expires_at <= now {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "expires_at must be in the future",
                "server_time": now
            })),
        )
            .into_response();
    }

    let note = req.note.as_deref().unwrap_or("");
    match db::batch_init_keys(&pool, req.count, req.expires_at, note).await {
        Ok((rows, keys)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "created": rows,
                "keys":    keys,
            })),
        )
            .into_response(),

        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}
