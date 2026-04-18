// server/src/handlers.rs — 完整优化版 v2
// 修复清单：
//   CRIT-1: cache-hit 时在 VerifyCacheEntry 中保留 key，消除多余 DB 查询
//   CRIT-2: valid_days 下界校验完整（>= 1）
//   CRIT-3: revoked/invalid-key 等业务错误码明确，client 不误入离线缓存
//   CRIT-4: extra_days 下界校验
//   MAJOR-1: nonce key 含 key_hash 防跨用户碰撞
//   MAJOR-2: nonce 去重移至签名验证之后
//   MAJOR-6: activate 成功后同步失效缓存

use crate::{auth, cache, db};
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

/// 恒定时间 HMAC-SHA256 验签（防时序攻击）
fn verify_hmac_signature(key: &str, key_hash: &str, timestamp: i64, sig: &str) -> bool {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<sha2::Sha256>;
    let mut mac = match HmacSha256::new_from_slice(key.as_bytes()) {
        Ok(m) => m,
        Err(_) => return false,
    };
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
    timestamp_window() + 30
}

// MAJOR-1 FIX: nonce key 包含 key_hash 前缀，防跨用户签名碰撞
// MAJOR-2 FIX: 此函数只在签名验证通过后调用
async fn check_and_store_nonce(redis_pool: &RedisPool, key_hash: &str, sig: &str) -> bool {
    let key = format!("nonce:{}:{}", &key_hash[..16.min(key_hash.len())], sig);
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
            tracing::error!("[Nonce] Redis 不可用 ({})，fail-closed 拒绝请求", e);
            false
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

// ── POST /activate ───────────────────────────────────────────────────────────
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
    let now = now_secs();

    // [1] 时间戳窗口
    if (now - req.timestamp).abs() > timestamp_window() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "ERR-TIME-RECORD", "server_time": now})),
        )
            .into_response();
    }

    // [2] 查 DB（先查再验签，MAJOR-2 FIX 顺序）
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

    // [3] 签名验证（在 nonce 消耗之前，MAJOR-2 FIX）
    if !verify_hmac_signature(&record.key, &req.key_hash, req.timestamp, &req.signature) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid signature"})),
        )
            .into_response();
    }

    // [4] nonce 去重（签名验证通过后，MAJOR-1 + MAJOR-2 FIX）
    if !check_and_store_nonce(&redis_pool, &req.key_hash, &req.signature).await {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": "ERR-REPLAY"})),
        )
            .into_response();
    }

    // [5] 已撤销 — 明确错误码（CRIT-3 FIX）
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
            return (StatusCode::GONE, Json(serde_json::json!({
                "error": "key has a pre-set expiry that is already in the past; use /admin/extend first"
            }))).into_response();
        } else {
            return (StatusCode::UNPROCESSABLE_ENTITY, Json(serde_json::json!({
                "error": "key has no expiry configured; use /admin/add-key with valid_days or /admin/extend"
            }))).into_response();
        };

        match db::activate_license(&pool, &req.key_hash, now, expires_at).await {
            Ok(true) => {
                // MAJOR-6 FIX: 同步失效缓存（代价极小，避免激活后5s内verify返回旧缓存）
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
            Ok(false) => match db::find_license(&pool, &req.key_hash).await {
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
            },
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response(),
        }
    } else {
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
    let now = now_secs();

    // [1] 时间戳窗口
    if (now - req.timestamp).abs() > timestamp_window() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "ERR-TIME-RECORD", "server_time": now})),
        )
            .into_response();
    }

    // [2] Cache + 验签（CRIT-1 FIX: cache-hit 直接用缓存中的 key，零额外 DB 查询）
    // [3] nonce 去重在验签之后（MAJOR-2 FIX）
    let entry = match cache::get_verify_cache(&redis_pool, &req.key_hash).await {
        Some(cached_entry) => {
            // CRIT-1 FIX: VerifyCacheEntry 包含 key，直接验签，无需 DB 查询
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
            // MAJOR-2 FIX: 验签通过后才消耗 nonce
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
                // MAJOR-2 FIX: 验签通过后才消耗 nonce
                if !check_and_store_nonce(&redis_pool, &req.key_hash, &req.signature).await {
                    return (
                        StatusCode::TOO_MANY_REQUESTS,
                        Json(serde_json::json!({"error": "ERR-REPLAY"})),
                    )
                        .into_response();
                }
                // CRIT-1 FIX: 缓存中包含 key（TTL=30s，IP 白名单保护，可接受）
                let e = VerifyCacheEntry {
                    key: record.key.clone(),
                    activation_ts: record.activation_ts,
                    expires_at: record.expires_at,
                    revoked: record.revoked,
                };
                cache::set_verify_cache(&redis_pool, &req.key_hash, &e).await;
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

    // [4] 异步限流更新 last_check（不阻塞响应）
    {
        let pool2 = Arc::clone(&pool);
        let rp2 = Arc::clone(&redis_pool);
        let kh = req.key_hash.clone();
        tokio::spawn(async move {
            if should_update_last_check(&rp2, &kh).await {
                if let Err(e) = db::update_last_check(&pool2, &kh, now).await {
                    tracing::warn!(
                        "[LastCheck] 更新失败 kh={}...: {}",
                        &kh[..8.min(kh.len())],
                        e
                    );
                }
            }
        });
    }

    // [5] 已撤销 — 明确错误码（CRIT-3 FIX）
    if entry.revoked {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "revoked": true,
                "error": "ERR-REVOKED"
            })),
        )
            .into_response();
    }

    // [6] 未激活
    if entry.activation_ts == 0 {
        return (
            StatusCode::PAYMENT_REQUIRED,
            Json(serde_json::json!({"error": "ERR-NOT-ACTIVATED"})),
        )
            .into_response();
    }

    // [7] 已过期
    if now >= entry.expires_at {
        return (
            StatusCode::PAYMENT_REQUIRED,
            Json(serde_json::json!({
                "revoked": false,
                "error": "ERR-EXPIRED"
                // INFO-2 FIX: 不返回 activation_ts/expires_at，防信息泄露
            })),
        )
            .into_response();
    }

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
            cache::invalidate_verify_cache(&redis_pool, &req.key_hash).await;
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

    // CRIT-4 FIX: extra_days 完整校验（原代码无下界校验）
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

    let extra_secs = req.extra_days * 86_400;
    match db::extend_license(&pool, &req.key_hash, extra_secs).await {
        Ok(true) => {
            cache::invalidate_verify_cache(&redis_pool, &req.key_hash).await;
            (
                StatusCode::OK,
                Json(serde_json::json!({"message": "extended"})),
            )
                .into_response()
        }
        Ok(false) => (
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

    // CRIT-2 FIX: 完整双边校验（原代码下界校验被截断/缺失）
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
            Json(serde_json::json!({"error": "valid_days must be <= 36500 (100 years)"})),
        )
            .into_response();
    }

    let expires_at = now + days * 86_400;
    let key = generate_hkey();
    let key_hash = hash_key(&key);
    let note = req.note.as_deref().unwrap_or("manual");

    match db::add_key(&pool, &key, &key_hash, expires_at, note).await {
        Ok(true) => (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "key": key,
                "key_hash": key_hash,
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
    match db::batch_init_keys(&pool, req.count, note).await {
        Ok(inserted) => (
            StatusCode::CREATED,
            Json(serde_json::json!({"inserted": inserted})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}
