// server/src/handlers.rs — 优化版 v6
//
// [BUG-01 FIX] Nonce 重复时返回 409 ERR-NONCE-REPLAY（原返回 403 混淆语义）
// [BUG-02 FIX] nonce_fallback 过期判断逻辑修正（见 nonce_fallback.rs）
// [BUG-03 FIX] HMAC 验签移至查 DB 之后、写 DB 之前
// [BUG-04 FIX] 并发激活竞态 -> rows_affected=0 返回 409 而非 500
// [BUG-06 FIX] cache::throttle_key() 统一命名空间前缀
// [BUG-11 FIX] /extend 后主动 invalidate verify cache（否则旧缓存继续命中）
// [BUG-12 FIX] extra_days * 86400 使用 checked_mul，防 i64 溢出
// [BUG-13 FIX] Nonce 检查移至 HMAC 验签之前，防止 DoS 攻击
//   攻击原理：攻击者发送大量无效签名 → 耗尽 nonce 配额 → 合法签名被误判为重放
//   修复：先检查 nonce（不耗资源），再验签（耗资源）
// [BUG-14 FIX] ERR_NOT_ACTIVATED 统一返回 409（激活操作用 409，verify 用 409）
//
// 重要安全顺序：Nonce检查 → HMAC验证 → 业务逻辑
//
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

static SERVER_ID: OnceLock<String>  = OnceLock::new();

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

/// key_hash 必须是 64 字符十六进制（SHA-256 输出）
fn validate_key_hash(key_hash: &str) -> bool {
    key_hash.len() == 64 && key_hash.chars().all(|c| c.is_ascii_hexdigit())
}

/// HMAC-SHA256 签名验证（常量时间比较防时序攻击）
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

    // [OPT-A] 长度不同时直接 false（expected 长度固定为 64），长度相同时常量时间比较
    if expected.len() != sig.len() {
        return false;
    }
    expected.as_bytes().ct_eq(sig.as_bytes()).into()
}

/// 生成随机 HKEY（格式: XXXX-XXXX-XXXX-XXXX-XXXX）
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

/// 时间窗口（秒），可通过环境变量覆盖，默认 300s
fn timestamp_window() -> i64 {
    static W: OnceLock<i64> = OnceLock::new();
    *W.get_or_init(|| {
        std::env::var("TIMESTAMP_WINDOW_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(300)
    })
}

/// Nonce TTL = 时间窗口 * 2 + 30s（确保窗口内不重放）
fn nonce_ttl() -> i64 {
    timestamp_window() * 2 + 30
}

/// Nonce 去重：优先 Redis SET NX EX，降级到内存 DashMap
///
/// 返回 true -> 首次见到此 nonce，请求合法
/// 返回 false -> nonce 重放，拒绝
///
/// [BUG-13 FIX] 此函数应在 HMAC 验签之前调用，防止 DoS 攻击
async fn check_and_store_nonce(pool: &RedisPool, key_hash: &str, sig: &str) -> bool {
    let key = format!("nonce:{}:{}", key_hash, sig);
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
            // [BUG-02 FIX] 修正后的 nonce_fallback 实现（语义正确）
            nonce_fallback::check_and_store(&key, nonce_ttl() as u64)
        }
    }
}

/// 节流：60s 内是否需要更新 last_check（限制 DB 写频率）
async fn should_update_last_check(pool: &RedisPool, key_hash: &str) -> bool {
    // [BUG-06 FIX] 使用统一命名空间的 throttle_key
    let throttle_key = cache::throttle_key(key_hash);
    let Ok(mut conn) = pool.get().await else {
        return true; // Redis 不可用时始终允许更新
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

// ═══════════════════════════════════════════════════════════════
// POST /activate
// ═══════════════════════════════════════════════════════════════
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
    // 1. 格式校验
    if !validate_key_hash(&req.key_hash) {
        return err(StatusCode::BAD_REQUEST, "invalid key_hash format");
    }

    // 2. 时间窗口校验
    let now = now_secs();
    if (now - req.timestamp).abs() > timestamp_window() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "ERR-TIME-RECORD",
                "server_time": now
            })),
        )
            .into_response();
    }

    // 3. 查 DB 获取 record（含明文 key，用于后续 HMAC 验签）
    let record = match db::find_license(&pool, &req.key_hash).await {
        Ok(Some(r)) => r,
        Ok(None) => return err(StatusCode::FORBIDDEN, "ERR-INVALID-KEY"),
        Err(e) => {
            tracing::error!("[Activate] DB error: {}", e);
            return err(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
        }
    };

    // 4. 吊销检查
    if record.revoked {
        return err(StatusCode::FORBIDDEN, "ERR-REVOKED");
    }

    // 5. [BUG-04 FIX] 已激活返回 409（原代码无此检查）
    if record.activation_ts > 0 {
        return err(StatusCode::CONFLICT, "ERR-ALREADY-ACTIVATED");
    }

    // 6. [BUG-13 FIX] Nonce 检查在 HMAC 之前（防 DoS）
    //    先检查 nonce 不消耗资源，只有通过后才执行昂贵的 HMAC 验签
    if !check_and_store_nonce(&redis_pool, &req.key_hash, &req.signature).await {
        return err(StatusCode::CONFLICT, "ERR-NONCE-REPLAY");
    }

    // 7. [BUG-03 FIX] HMAC 验签（依赖 record.key，必须在查 DB 之后）
    if !verify_hmac_signature(&record.key, &req.key_hash, req.timestamp, &req.signature) {
        return err(StatusCode::FORBIDDEN, "ERR-INVALID-KEY");
    }

    // 8. 计算有效期
    let activation_ts = now;
    let default_days: i64 = std::env::var("DEFAULT_LICENSE_DAYS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(365);

    // [BUG-12 FIX] checked_mul 防溢出
    let extra_secs = default_days
        .checked_mul(86400)
        .unwrap_or(db::MAX_EXTEND_SECS)
        .clamp(1, db::MAX_EXTEND_SECS);
    let expires_at = activation_ts + extra_secs;

    // 9. 写 DB（条件更新：activation_ts = 0 AND NOT revoked，防并发）
    match db::activate_license(&pool, &req.key_hash, activation_ts, expires_at).await {
        Ok(true) => {
            tracing::info!("[Activate] activated key_hash={}...", &req.key_hash[..8]);
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "activation_ts": activation_ts,
                    "expires_at": expires_at,
                    "revoked": false,
                })),
            )
                .into_response()
        }
        // [BUG-04 FIX] rows_affected=0 → 并发激活竞态 → 409
        Ok(false) => {
            tracing::warn!(
                "[Activate] concurrent activation for {}...",
                &req.key_hash[..8]
            );
            err(StatusCode::CONFLICT, "ERR-ALREADY-ACTIVATED")
        }
        Err(e) => {
            tracing::error!("[Activate] DB write: {}", e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// POST /verify
// ═══════════════════════════════════════════════════════════════
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
            Json(serde_json::json!({
                "error": "ERR-TIME-RECORD",
                "server_time": now
            })),
        )
            .into_response();
    }

    // [BUG-05 FIX] 先查 revoke（内存 map 最快路径 → Redis tombstone）
    if cache::is_revoked(&redis_pool, &req.key_hash).await {
        return err(StatusCode::FORBIDDEN, "ERR-REVOKED");
    }

    // 缓存命中路径（仍需 Nonce 检查 + HMAC 验签）
    if let Some(entry) = cache::get_verify_cache(&redis_pool, &req.key_hash).await {
        // [BUG-13 FIX] Nonce 检查在 HMAC 之前（防 DoS）
        // 注意：缓存命中路径不常见，主要防止恶意重放
        if !check_and_store_nonce(&redis_pool, &req.key_hash, &req.signature).await {
            return err(StatusCode::CONFLICT, "ERR-NONCE-REPLAY");
        }

        // [BUG-11 FIX] cache hit 后仍验证 HMAC（防止旧缓存在 revoke 之后被旧签名绕过）
        if !verify_hmac_signature(&entry.key, &req.key_hash, req.timestamp, &req.signature) {
            return err(StatusCode::FORBIDDEN, "ERR-INVALID-KEY");
        }

        if entry.expires_at < now {
            return err(StatusCode::CONFLICT, "ERR-EXPIRED");
        }

        // 更新 last_check（节流）
        if should_update_last_check(&redis_pool, &req.key_hash).await {
            let _ = db::update_last_check(&pool, &req.key_hash, now).await;
        }

        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "activation_ts": entry.activation_ts,
                "expires_at": entry.expires_at,
                "revoked": false,
            })),
        )
            .into_response();
    }

    // 缓存未命中：查 DB
    let record = match db::find_license(&pool, &req.key_hash).await {
        Ok(Some(r)) => r,
        Ok(None) => return err(StatusCode::FORBIDDEN, "ERR-INVALID-KEY"),
        Err(e) => {
            tracing::error!("[Verify] DB error: {}", e);
            return err(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
        }
    };

    if record.revoked {
        cache::mark_revoked_in_memory(&req.key_hash, record.expires_at);
        return err(StatusCode::FORBIDDEN, "ERR-REVOKED");
    }

    // activation_ts == 0 表示尚未激活
    if record.activation_ts == 0 {
        // [BUG-14 FIX] 统一返回 409，与 activate 保持一致
        return err(StatusCode::CONFLICT, "ERR-NOT-ACTIVATED");
    }

    // [BUG-13 FIX] Nonce 检查在 HMAC 之前（防 DoS）
    // 这是主要的 verify 路径，nonce 检查尤为重要
    if !check_and_store_nonce(&redis_pool, &req.key_hash, &req.signature).await {
        return err(StatusCode::CONFLICT, "ERR-NONCE-REPLAY");
    }

    if !verify_hmac_signature(&record.key, &req.key_hash, req.timestamp, &req.signature) {
        return err(StatusCode::FORBIDDEN, "ERR-INVALID-KEY");
    }

    if record.expires_at < now {
        return err(StatusCode::CONFLICT, "ERR-EXPIRED");
    }

    // 写入缓存（用于后续快速验证）
    cache::set_verify_cache(
        &redis_pool,
        &req.key_hash,
        &VerifyCacheEntry {
            key: record.key,
            activation_ts: record.activation_ts,
            expires_at: record.expires_at,
        },
    )
    .await;

    // 更新 last_check（节流）
    if should_update_last_check(&redis_pool, &req.key_hash).await {
        let _ = db::update_last_check(&pool, &req.key_hash, now).await;
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "activation_ts": record.activation_ts,
            "expires_at": record.expires_at,
            "revoked": false,
        })),
    )
        .into_response()
}

// ═══════════════════════════════════════════════════════════════
// GET /health
// ═══════════════════════════════════════════════════════════════
pub async fn health() -> impl IntoResponse {
    let (nonce_total, nonce_rejected, nonce_map_size) = nonce_fallback::get_nonce_stats();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "ok",
            "nonce_stats": {
                "total_checks": nonce_total,
                "rejected": nonce_rejected,
                "map_size": nonce_map_size
            }
        })),
    )
        .into_response();
}

fn err(code: StatusCode, msg: &str) -> axum::response::Response {
    (code, Json(serde_json::json!({ "error": msg }))).into_response()
}

// ═══════════════════════════════════════════════════════════════
// Admin endpoints（均需 token 验证）
// ═══════════════════════════════════════════════════════════════
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

    // [BUG-11 FIX] revoke 后立即 invalidate verify cache
    cache::invalidate_verify_cache(&redis_pool, &req.key_hash).await;

    // 写 30 天 tombstone 到内存 map（加速后续 verify 拦截）
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

    // [BUG-12 FIX] checked_mul 防溢出
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
            // [BUG-11 FIX] 延期后 invalidate verify cache
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
    Extension(admin): Extension<Arc<String>>,
    Json(req): Json<BatchInitReq>,
) -> impl IntoResponse {
    if !auth::verify_admin_token(&req.token, &admin) {
        return err(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    let count = req.count.min(1000);
    let note = req.note.as_deref().unwrap_or("");
    let now = now_secs();
    let mut keys = Vec::with_capacity(count);
    for _ in 0..count {
        let hkey = generate_hkey();
        let key_hash = hash_key(&hkey);
        if db::insert_license(&pool, &hkey, &key_hash, now, note)
            .await
            .is_ok()
        {
            keys.push(serde_json::json!({ "key": hkey, "key_hash": key_hash }));
        }
    }
    let count = keys.len();
    (
        StatusCode::OK,
        Json(serde_json::json!({ "keys": keys, "count": count })),
    )
        .into_response()
}
