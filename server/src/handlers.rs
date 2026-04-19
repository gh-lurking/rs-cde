// server/src/handlers.rs — 优化版 v8
// 修复汇总:
// ✅ CRIT-1 FIX: cache hit 时 tombstone 优先，key 为空串时不做 HMAC 验签，回源 DB
// ✅ CRIT-3 FIX: 所有 expires_at/activation_ts 比较前确保 > 0
// ✅ MAJOR-3 FIX: tombstone 使用 tombstone_ttl()（cache.rs 已修复）
// ✅ MINOR-4 FIX: tokio::spawn 内计算 req_time，无跨 await 借用
// ✅ OPT: SERVER_ID 使用 OnceLock 缓存，避免每次请求读环境变量

use crate::{auth, cache, db, nonce_fallback};
use axum::{
    extract::{Extension, Json, Query},
    http::StatusCode,
    response::IntoResponse,
};
use cache::{RedisPool, VerifyCacheEntry};
use db::DbPool;
use hex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

// ✅ OPT: 缓存 SERVER_ID，避免每次验签读环境变量
static SERVER_ID: OnceLock<String> = OnceLock::new();

fn get_server_id() -> &'static str {
    SERVER_ID.get_or_init(|| std::env::var("SERVER_ID").unwrap_or_default())
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
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<sha2::Sha256>;
    // ✅ OPT: 使用缓存的 SERVER_ID
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
    // 常量时间比较，防止时序攻击
    expected
        .as_bytes()
        .iter()
        .zip(sig.as_bytes())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
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
                "[Nonce] Redis 不可用 ({})，降级到内存 nonce（单节点有效）",
                e
            );
            nonce_fallback::check_and_store(&key, nonce_ttl() as u64)
        }
    }
}

async fn should_update_last_check(redis_pool: &RedisPool, key_hash: &str) -> bool {
    let throttle_key = format!("lc_throttle:{}", key_hash);
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

    // [2] 查 DB（用 key_hash 查询，不暴露明文 key）
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

    // [3] HMAC 验签（使用 DB 中的明文 key）
    if !verify_hmac_signature(&record.key, &req.key_hash, req.timestamp, &req.signature) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid signature"})),
        )
            .into_response();
    }

    // [4] nonce 防重放
    if !check_and_store_nonce(&redis_pool, &req.key_hash, &req.signature).await {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": "duplicate request (nonce reuse)"})),
        )
            .into_response();
    }

    // [5] 业务状态检查
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
            Json(serde_json::json!({"error": "ERR-ALREADY-ACTIVATED",
                "activation_ts": record.activation_ts,
                "expires_at": record.expires_at})),
        )
            .into_response();
    }
    // ✅ CRIT-3 FIX: expires_at 必须 > 0（admin 设置时已保证，但防御性校验）
    if record.expires_at == 0 {
        tracing::error!(
            "[Activate] key_hash={}... expires_at=0，DB 数据异常",
            &req.key_hash[..8.min(req.key_hash.len())]
        );
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "invalid license record: expires_at=0"})),
        )
            .into_response();
    }

    // [6] 执行激活（DB 层有 AND activation_ts=0 防重复）
    let activated_ts = now;
    match db::activate_license(&pool, &req.key_hash, activated_ts, record.expires_at).await {
        Ok(true) => {
            tracing::info!(
                "[Activate] key_hash={}... 激活成功，expires_at={}",
                &req.key_hash[..8.min(req.key_hash.len())],
                record.expires_at
            );
            // 激活后清除旧缓存（若有），使 verify 下次回源
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
        Ok(false) => {
            // 另一个请求先激活了（race condition，正常）
            (
                StatusCode::CONFLICT,
                Json(serde_json::json!({"error": "ERR-ALREADY-ACTIVATED"})),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

// ── POST /verify ──────────────────────────────────────────────────────────────

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

    // ✅ CRIT-1 FIX: cache hit 分支完整重写
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

        // Step B: tombstone key 为空串 => 缓存数据损坏，回源 DB
        // （正常 entry 的 key 是密钥明文，不为空）
        if cached_entry.key.is_empty() {
            tracing::warn!("[Verify] cache entry key 为空但 revoked=false，数据异常，回源 DB");
            // fall through to DB lookup
        } else {
            // Step C: HMAC 验签（使用缓存的明文 key）
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

            // Step D: nonce 防重放
            if !check_and_store_nonce(&redis_pool, &req.key_hash, &req.signature).await {
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(serde_json::json!({"error": "duplicate request (nonce reuse)"})),
                )
                    .into_response();
            }

            // Step E: ✅ CRIT-3 FIX: 校验 activation_ts > 0 && expires_at > 0
            if cached_entry.activation_ts <= 0 || cached_entry.expires_at <= 0 {
                tracing::warn!(
                    "[Verify] 缓存了未激活记录 (activation_ts={}, expires_at={})，回源 DB",
                    cached_entry.activation_ts,
                    cached_entry.expires_at
                );
                // 主动清除脏缓存，回源 DB
                cache::invalidate_verify_cache(&redis_pool, &req.key_hash).await;
                // fall through
            } else if now >= cached_entry.expires_at {
                // Step F: 过期检查（此时 expires_at > 0 已保证）
                let days = (now - cached_entry.expires_at) / 86400;
                return (
                    StatusCode::GONE,
                    Json(serde_json::json!({"error": "ERR-EXPIRED", "expired_days": days})),
                )
                    .into_response();
            } else {
                // ✅ Cache hit 且合法：异步更新 last_check
                if should_update_last_check(&redis_pool, &req.key_hash).await {
                    let pool_clone = pool.clone();
                    let key_hash = req.key_hash.clone();
                    tokio::spawn(async move {
                        // ✅ MINOR-4 FIX: req_time 在 spawn 内计算
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

    // ── DB 回源 ──────────────────────────────────────────────────────────────
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

    // HMAC 验签（回源后用 DB 的明文 key）
    if !verify_hmac_signature(&record.key, &req.key_hash, req.timestamp, &req.signature) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid signature"})),
        )
            .into_response();
    }

    // nonce 防重放
    if !check_and_store_nonce(&redis_pool, &req.key_hash, &req.signature).await {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": "duplicate request (nonce reuse)"})),
        )
            .into_response();
    }

    // 业务状态检查
    if record.revoked {
        // ✅ revoke 时写入 tombstone（长 TTL）
        cache::set_revoked_tombstone(&redis_pool, &req.key_hash).await;
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "ERR-REVOKED"})),
        )
            .into_response();
    }

    // ✅ CRIT-3 FIX: 未激活检查在 expires_at 检查之前
    if record.activation_ts == 0 || record.expires_at == 0 {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "ERR-NOT-ACTIVATED"})),
        )
            .into_response();
    }

    // 过期检查（此时 expires_at > 0 已保证）
    if now >= record.expires_at {
        let days = (now - record.expires_at) / 86400;
        return (
            StatusCode::GONE,
            Json(serde_json::json!({"error": "ERR-EXPIRED", "expired_days": days})),
        )
            .into_response();
    }

    // ✅ 写入缓存（仅写入合法且已激活的记录）
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
            // ✅ MINOR-4 FIX: req_time 在 spawn 内计算
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

// ── GET /health ───────────────────────────────────────────────────────────────

pub async fn health() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({"status": "ok"})))
}

// ── Admin handlers ─────────────────────────────────────────────────────────────

fn require_admin(
    token: &Arc<String>,
    provided: &str,
) -> Result<(), (StatusCode, axum::Json<serde_json::Value>)> {
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
            // ✅ 立即写入 tombstone（使用 tombstone_ttl() 的长 TTL）
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
    if req.extra_days <= 0 || req.extra_days > 3650 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "extra_days must be 1-3650"})),
        )
            .into_response();
    }
    let extra_secs = req.extra_days * 86400;
    match db::extend_license(&pool, &req.key_hash, extra_secs).await {
        Ok(Some(new_expires_at)) => {
            // 延期后使缓存失效，让下次 verify 回源
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
    if req.expires_at <= now {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "expires_at is in the past"})),
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
                "key": hkey,
                "key_hash": key_hash,
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
    if req.expires_at <= now_secs() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "expires_at is in the past"})),
        )
            .into_response();
    }
    let note = req.note.as_deref().unwrap_or("");
    // ✅ MINOR-2 FIX: 返回 (rows_affected, Vec<String>) 包含 key 列表
    match db::batch_init_keys(&pool, req.count, req.expires_at, note).await {
        Ok((rows, keys)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "created": rows,
                "keys": keys,
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
