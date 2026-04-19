// server/src/handlers.rs — 优化版 v7 (Bug修复版)
//
// ✅ CRIT-1 FIX: cache hit 分支先判断 tombstone(revoked=true)，再用 cached_entry.key 验签
// ✅ CRIT-3 FIX: 写缓存条件增加 expires_at > 0 显式断言
// ✅ MAJOR-3 FIX: tombstone 使用 tombstone_ttl()（set_revoked_tombstone 已更新）
// ✅ MINOR-4 FIX: tokio::spawn 前捕获 req_time

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
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

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
    let server_id = std::env::var("SERVER_ID").unwrap_or_default();
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
                "[Nonce] Redis 不可用 ({})，降级到内存 nonce（安全性略降）",
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

// ── POST /activate ──────────────────────────────────────────────────────────
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

    // [1] 时间戳窗口
    if (now - req.timestamp).abs() > timestamp_window() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "ERR-TIME-RECORD", "server_time": now})),
        )
            .into_response();
    }

    // [2] 查 DB（取 key 用于验签）
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

    // [3] 验签（先于 nonce 消耗）
    if !verify_hmac_signature(&record.key, &req.key_hash, req.timestamp, &req.signature) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid signature"})),
        )
            .into_response();
    }

    // [4] nonce 去重（验签通过后才消耗 nonce slot）
    if !check_and_store_nonce(&redis_pool, &req.key_hash, &req.signature).await {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": "ERR-REPLAY"})),
        )
            .into_response();
    }

    // [5] 已撤销
    if record.revoked {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "ERR-REVOKED"})),
        )
            .into_response();
    }

    if record.activation_ts == 0 {
        let expires_at = if record.expires_at > now {
            record.expires_at
        } else if record.expires_at > 0 {
            return (
                StatusCode::GONE,
                Json(serde_json::json!({
                    "error": "key has a pre-set expiry that is already in the past"
                })),
            )
                .into_response();
        } else {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({
                    "error": "key has no expiry configured; use /admin/add-key with valid_days"
                })),
            )
                .into_response();
        };

        match db::activate_license(&pool, &req.key_hash, now, expires_at).await {
            Ok(true) => {
                cache::invalidate_verify_cache(&redis_pool, &req.key_hash).await;
                (
                    StatusCode::CREATED,
                    Json(serde_json::json!({
                        "activation_ts": now,
                        "expires_at": expires_at,
                        "message": "Activated."
                    })),
                )
                    .into_response()
            }
            Ok(false) => {
                cache::invalidate_verify_cache(&redis_pool, &req.key_hash).await;
                match db::find_license(&pool, &req.key_hash).await {
                    Ok(Some(r)) if r.activation_ts != 0 => (
                        StatusCode::OK,
                        Json(serde_json::json!({
                            "activation_ts": r.activation_ts,
                            "expires_at": r.expires_at,
                            "message": "Already activated (concurrent race, returning DB values)"
                        })),
                    )
                        .into_response(),
                    _ => (
                        StatusCode::CONFLICT,
                        Json(serde_json::json!({"error": "concurrent activation conflict"})),
                    )
                        .into_response(),
                }
            }
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response(),
        }
    } else {
        if now >= record.expires_at {
            return (
                StatusCode::GONE,
                Json(serde_json::json!({
                    "error": "ERR-EXPIRED",
                    "activation_ts": record.activation_ts,
                    "expires_at": record.expires_at,
                    "message": "Already activated but license has expired"
                })),
            )
                .into_response();
        }
        (
            StatusCode::OK,
            Json(serde_json::json!({
                "activation_ts": record.activation_ts,
                "expires_at": record.expires_at,
                "message": "Already activated (returning original timestamps)"
            })),
        )
            .into_response()
    }
}

// ── POST /verify ─────────────────────────────────────────────────────────────
#[derive(Deserialize)]
pub struct VerifyReq {
    key_hash: String,
    timestamp: i64,
    signature: String,
}

#[derive(Serialize)]
struct VerifyResp {
    activation_ts: i64,
    expires_at: i64,
    revoked: bool,
}

pub async fn verify(
    Extension(pool): Extension<Arc<DbPool>>,
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

    // [1] 时间戳窗口
    if (now - req.timestamp).abs() > timestamp_window() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "ERR-TIME-RECORD", "server_time": now})),
        )
            .into_response();
    }

    // [2] 取 entry（Cache → DB）
    let entry = match cache::get_verify_cache(&redis_pool, &req.key_hash).await {
        Some(cached_entry) => {
            // ✅ CRIT-1 FIX: 先检查 tombstone(revoked)，再用 cached_entry.key 验签
            // tombstone.key = "" → 若先验签，空 key 会产生可预测的 HMAC 值
            if cached_entry.revoked {
                return (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({"error": "ERR-REVOKED"})),
                )
                    .into_response();
            }

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
            if !check_and_store_nonce(&redis_pool, &req.key_hash, &req.signature).await {
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(serde_json::json!({"error": "ERR-REPLAY"})),
                )
                    .into_response();
            }
            cached_entry
        }
        None => match db::find_license(&pool, &req.key_hash).await {
            Ok(Some(record)) => {
                if !verify_hmac_signature(&record.key, &req.key_hash, req.timestamp, &req.signature)
                {
                    return (
                        StatusCode::UNAUTHORIZED,
                        Json(serde_json::json!({"error": "invalid signature"})),
                    )
                        .into_response();
                }
                if !check_and_store_nonce(&redis_pool, &req.key_hash, &req.signature).await {
                    return (
                        StatusCode::TOO_MANY_REQUESTS,
                        Json(serde_json::json!({"error": "ERR-REPLAY"})),
                    )
                        .into_response();
                }
                let e = VerifyCacheEntry {
                    key: record.key.clone(),
                    activation_ts: record.activation_ts,
                    expires_at: record.expires_at,
                    revoked: record.revoked,
                };
                // ✅ CRIT-3 FIX: 写缓存条件增加 expires_at > 0 显式断言
                // 防止系统时钟极端异常(now≈0)时将无效条目写入缓存
                if !e.revoked
                    && e.activation_ts > 0
                    && e.expires_at > 0       // ← CRIT-3 新增
                    && e.expires_at > now
                {
                    cache::set_verify_cache(&redis_pool, &req.key_hash, &e).await;
                }
                e
            }
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
        },
    };

    // [3] 异步 last_check 更新
    // ✅ MINOR-4 FIX: spawn 前捕获 req_time，保证时间戳准确
    let req_time = now_secs();
    {
        let pool2 = Arc::clone(&pool);
        let rp2 = Arc::clone(&redis_pool);
        let kh = req.key_hash.clone();
        tokio::spawn(async move {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), async move {
                if should_update_last_check(&rp2, &kh).await {
                    if let Err(e) = db::update_last_check(&pool2, &kh, req_time).await {
                        tracing::warn!(
                            "[LastCheck] 更新失败 kh={}...: {}",
                            &kh[..8.min(kh.len())],
                            e
                        );
                    }
                }
            })
            .await;
        });
    }

    // [4] 已撤销 → 403（cache hit 路径已在上方提前返回，此处为 DB 路径兜底）
    if entry.revoked {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "ERR-REVOKED"})),
        )
            .into_response();
    }

    // [5] 未激活 → 403
    if entry.activation_ts == 0 {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "ERR-NOT-ACTIVATED"})),
        )
            .into_response();
    }

    // [6] 已过期 → 410
    if now >= entry.expires_at {
        return (
            StatusCode::GONE,
            Json(serde_json::json!({"error": "ERR-EXPIRED"})),
        )
            .into_response();
    }

    // [7] 正常响应 → 200
    (
        StatusCode::OK,
        Json(VerifyResp {
            activation_ts: entry.activation_ts,
            expires_at: entry.expires_at,
            revoked: false,
        }),
    )
        .into_response()
}

// ── GET /health ───────────────────────────────────────────────────────────────
pub async fn health(
    Extension(pool): Extension<Arc<DbPool>>,
    Extension(redis_pool): Extension<Arc<RedisPool>>,
) -> impl IntoResponse {
    let pg_ok = sqlx::query("SELECT 1").execute(pool.as_ref()).await.is_ok();
    let redis_ok = redis_pool.get().await.is_ok();
    if pg_ok && redis_ok {
        (StatusCode::OK, Json(serde_json::json!({"status": "ok"})))
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "status": "degraded",
                "pg": pg_ok,
                "redis": redis_ok
            })),
        )
    }
}

fn check_admin(provided: &str, expected: &Arc<String>) -> bool {
    auth::verify_admin_token(provided, expected)
}

// ── GET /admin/licenses ───────────────────────────────────────────────────────
#[derive(Deserialize)]
pub struct AdminQuery {
    token: String,
}

pub async fn list_licenses(
    Extension(pool): Extension<Arc<DbPool>>,
    Extension(admin_token): Extension<Arc<String>>,
    Query(q): Query<AdminQuery>,
) -> impl IntoResponse {
    if !check_admin(&q.token, &admin_token) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "unauthorized"})),
        )
            .into_response();
    }
    match db::list_all_licenses(&pool).await {
        Ok(list) => (StatusCode::OK, Json(serde_json::json!(list))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

// ── POST /admin/revoke ────────────────────────────────────────────────────────
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
    if !check_admin(&req.token, &admin_token) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "unauthorized"})),
        )
            .into_response();
    }
    let reason = req.reason.as_deref().unwrap_or("revoked by admin");
    match db::revoke_license(&pool, &req.key_hash, reason).await {
        Ok(()) => {
            // ✅ MAJOR-3: tombstone 使用更长 TTL（见 cache::set_revoked_tombstone）
            cache::set_revoked_tombstone(&redis_pool, &req.key_hash).await;
            (
                StatusCode::OK,
                Json(serde_json::json!({"message": "revoked"})),
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

// ── POST /admin/extend ────────────────────────────────────────────────────────
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
    if !check_admin(&req.token, &admin_token) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "unauthorized"})),
        )
            .into_response();
    }
    if req.extra_days < 1 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "extra_days must be >= 1"})),
        )
            .into_response();
    }
    if req.extra_days > 36500 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "extra_days must be <= 36500"})),
        )
            .into_response();
    }
    let record = match db::find_license(&pool, &req.key_hash).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "key not found"})),
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
    if record.revoked {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "key is revoked, cannot extend"})),
        )
            .into_response();
    }
    if record.activation_ts == 0 {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({
                "error": "ERR-NOT-ACTIVATED",
                "message": "未激活密钥不支持 extend。请先激活，或使用 /admin/add-key 的 valid_days 设置激活后有效期。"
            })),
        )
            .into_response();
    }
    let extra_secs = req.extra_days * 86400;
    match db::extend_license(&pool, &req.key_hash, extra_secs).await {
        Ok(Some(new_expires)) => {
            cache::invalidate_verify_cache(&redis_pool, &req.key_hash).await;
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "message": "license extended successfully",
                    "expires_at": new_expires
                })),
            )
                .into_response()
        }
        Ok(None) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "key not found or revoked"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

// ── POST /admin/add-key ───────────────────────────────────────────────────────
#[derive(Deserialize)]
pub struct AddKeyReq {
    token: String,
    valid_days: Option<i64>,
    note: Option<String>,
}

pub async fn add_key(
    Extension(pool): Extension<Arc<DbPool>>,
    Extension(admin_token): Extension<Arc<String>>,
    Json(req): Json<AddKeyReq>,
) -> impl IntoResponse {
    if !check_admin(&req.token, &admin_token) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "unauthorized"})),
        )
            .into_response();
    }
    let now = now_secs();
    let days = req.valid_days.unwrap_or(365);
    if days < 1 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "valid_days must be >= 1"})),
        )
            .into_response();
    }
    if days > 36500 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "valid_days must be <= 36500"})),
        )
            .into_response();
    }
    let key = generate_hkey();
    let key_hash = hash_key(&key);
    let expires_at = now + days * 86400;
    let note = req.note.as_deref().unwrap_or("");
    match db::add_key(&pool, &key, &key_hash, expires_at, note).await {
        Ok(true) => (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "key": key,
                "key_hash": key_hash,
                "expires_at": expires_at,
                // ✅ MAJOR-2: 明确说明 expires_at 语义，并返回 created_at 供管理员计算激活窗口
                "expires_at_note": "从创建时刻算起的绝对截止日期，非激活后有效期",
                "created_at": now,
            })),
        )
            .into_response(),
        Ok(false) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "key_hash conflict (extremely rare)"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

// ── POST /admin/batch-init ────────────────────────────────────────────────────
#[derive(Deserialize)]
pub struct BatchInitReq {
    token: String,
    count: u32,
    note: Option<String>,
}

pub async fn batch_init(
    Extension(pool): Extension<Arc<DbPool>>,
    Extension(admin_token): Extension<Arc<String>>,
    Json(req): Json<BatchInitReq>,
) -> impl IntoResponse {
    if !check_admin(&req.token, &admin_token) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "unauthorized"})),
        )
            .into_response();
    }
    if req.count == 0 || req.count > 10_000 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "count must be 1..=10000"})),
        )
            .into_response();
    }
    let note = req.note.as_deref().unwrap_or("batch");
    // ✅ MINOR-2 FIX: batch_init_keys 现在返回 (inserted, keys) 元组
    match db::batch_init_keys(&pool, req.count, note).await {
        Ok((inserted, keys)) => (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "inserted": inserted,
                "keys": keys,   // ✅ MINOR-2: 返回生成的 key 列表
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
