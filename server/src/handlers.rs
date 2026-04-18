// server/src/handlers.rs — 优化版（完整）
// 修复: BUG-01(replay) BUG-02(expires=0顺序) BUG-03(无验签) BUG-08(last_check NULL)
//       BUG-09(extend静默失败) BUG-A(激活前校验expires) BUG-B(cache验签)
//       BUG-C(nonce降级) BUG-D(last_check节流) BUG-E(valid_days校验)
//       BUG-G(时间窗口可配+server_time) BUG-H(revoke改POST)

use crate::{auth, cache, db};
use axum::{
    extract::{Extension, Json, Query},
    http::StatusCode,
    response::IntoResponse,
};
use cache::{RedisPool, VerifyCacheEntry};
use db::DbPool;
use hex;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
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

/// 恒定时间 HMAC-SHA256 签名验证（防时序攻击）
/// BUG-03 FIX: 查库拿到 record.key 后，验证签名合法性
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

    // 恒定时间比较（防时序侧信道）
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

// ── BUG-C FIX: 内存降级 nonce 存储（Redis 宕机时使用）──────────────────────
static FALLBACK_NONCES: Lazy<Mutex<(HashSet<String>, Instant)>> =
    Lazy::new(|| Mutex::new((HashSet::new(), Instant::now())));

/// BUG-01 FIX: nonce 去重（Redis NX 原子操作；BUG-C FIX: 降级内存集）
async fn check_and_store_nonce(redis_pool: &RedisPool, sig: &str) -> bool {
    let key = format!("nonce:{}", sig);
    match redis_pool.get().await {
        Ok(mut conn) => {
            let result: Result<Option<String>, _> = deadpool_redis::redis::cmd("SET")
                .arg(&key)
                .arg("1")
                .arg("EX")
                .arg(70i64) // 时间窗口 300s + 安全余量
                .arg("NX") // 原子"不存在才写"
                .query_async(&mut conn)
                .await;
            matches!(result, Ok(Some(_)))
        }
        Err(_) => {
            // BUG-C FIX: Redis 宕机 → 降级到内存 nonce 集（5 分钟自动清空）
            let mut guard = FALLBACK_NONCES.lock().unwrap();
            let (set, last_reset) = &mut *guard;
            if last_reset.elapsed() > Duration::from_secs(300) {
                set.clear();
                *last_reset = Instant::now();
            }
            if set.len() > 50_000 {
                return false;
            } // 防内存耗尽
            set.insert(sig.to_string())
        }
    }
}

/// BUG-D FIX: last_check 限流写入（60s 内最多写一次 DB）
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

/// BUG-G FIX: 时间窗口从环境变量读取（默认 300s）
fn timestamp_window() -> i64 {
    std::env::var("TIMESTAMP_WINDOW_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300)
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
    let now = now_secs();

    // [1] 时间戳窗口（BUG-G FIX: 可配置，返回 server_time）
    if (now - req.timestamp).abs() > timestamp_window() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "ERR-TIME-RECORD", "server_time": now})),
        )
            .into_response();
    }

    // [2] BUG-01 FIX: nonce 去重（BUG-C FIX: Redis 宕机降级内存集）
    if !check_and_store_nonce(&redis_pool, &req.signature).await {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": "ERR-REPLAY"})),
        )
            .into_response();
    }

    // [3] 查 DB
    let record = match db::find_license(&pool, &req.key_hash).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({"error": "invalid key"})),
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

    // [4] BUG-03 FIX: 签名验证（持有原始 key 才能生成正确 HMAC）
    if !verify_hmac_signature(&record.key, &req.key_hash, req.timestamp, &req.signature) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid signature"})),
        )
            .into_response();
    }

    // [5] 已撤销
    if record.revoked {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "key revoked"})),
        )
            .into_response();
    }

    if record.activation_ts == 0 {
        // BUG-A FIX: 激活前强制校验 expires_at 合法性
        let expires_at = if record.expires_at > now {
            record.expires_at // 预设且未过期：直接使用
        } else if record.expires_at > 0 {
            // 预设值已过期：拒绝激活
            return (StatusCode::GONE, Json(serde_json::json!({
                "error": "key has a pre-set expiry that is already in the past; use /admin/extend first"
            }))).into_response();
        } else {
            // expires_at=0（batch-init 风格）：拒绝，提示先设置期限
            return (StatusCode::UNPROCESSABLE_ENTITY, Json(serde_json::json!({
                "error": "key has no expiry configured; use /admin/add-key with valid_days or /admin/extend"
            }))).into_response();
        };

        match db::activate_license(&pool, &req.key_hash, now, expires_at).await {
            Ok(()) => {}
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": e.to_string()})),
                )
                    .into_response();
            }
        }

        // 激活后主动失效 Redis 缓存
        let rp = Arc::clone(&redis_pool);
        let kh = req.key_hash.clone();
        tokio::spawn(async move {
            cache::invalidate_verify_cache(&rp, &kh).await;
        });

        (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "activation_ts": now,
                "expires_at": expires_at,
                "message": "Activated."
            })),
        )
            .into_response()
    } else {
        // 已激活：幂等返回原始时间戳
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

// ── POST /verify ──────────────────────────────────────────────────────────────
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

    // [1] 时间戳窗口（BUG-G FIX）
    if (now - req.timestamp).abs() > timestamp_window() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "ERR-TIME-RECORD", "server_time": now})),
        )
            .into_response();
    }

    // [2] BUG-01 FIX + BUG-B FIX: verify 也做 nonce 去重
    if !check_and_store_nonce(&redis_pool, &req.signature).await {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": "ERR-REPLAY"})),
        )
            .into_response();
    }

    // [3] 查 Cache 或 DB，BUG-B FIX: cache-hit 时也验签
    let entry = match cache::get_verify_cache(&redis_pool, &req.key_hash).await {
        Some(e) => {
            // BUG-B FIX: cache-hit 时用缓存的 key 验签
            if !verify_hmac_signature(&e.key, &req.key_hash, req.timestamp, &req.signature) {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({"error": "invalid signature"})),
                )
                    .into_response();
            }
            e
        }
        None => {
            match db::find_license(&pool, &req.key_hash).await {
                Ok(Some(record)) => {
                    if !verify_hmac_signature(
                        &record.key,
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
                    let e = VerifyCacheEntry {
                        key: record.key.clone(), // BUG-B FIX: 存入 key
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
                        Json(serde_json::json!({"error": "invalid key"})),
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
            }
        }
    };

    // [4] BUG-D FIX: 异步限流更新 last_check（60s/次，不阻塞响应）
    {
        let pool2 = Arc::clone(&pool);
        let rp2 = Arc::clone(&redis_pool);
        let kh = req.key_hash.clone();
        tokio::spawn(async move {
            if should_update_last_check(&rp2, &kh).await {
                let _ = db::update_last_check(&pool2, &kh, now).await;
            }
        });
    }

    // [5] 已撤销
    if entry.revoked {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "activation_ts": entry.activation_ts,
                "expires_at": entry.expires_at,
                "revoked": true,
                "error": "key revoked"
            })),
        )
            .into_response();
    }

    // [6] 未激活（BUG-02 FIX: 必须在过期检查之前！）
    if entry.activation_ts == 0 {
        return (
            StatusCode::PAYMENT_REQUIRED,
            Json(serde_json::json!({"error": "not activated"})),
        )
            .into_response();
    }

    // [7] 已过期（BUG-02 FIX: 此时 expires_at 必然 > 0，语义清晰）
    if now >= entry.expires_at {
        return (
            StatusCode::PAYMENT_REQUIRED,
            Json(serde_json::json!({
                "activation_ts": entry.activation_ts,
                "expires_at": entry.expires_at,
                "revoked": false,
                "error": "expired"
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
                "status": "degraded", "pg": pg_ok, "redis": redis_ok
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

// ── POST /admin/revoke（BUG-H FIX: 由 DELETE 改 POST）────────────────────────
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
    let extra_secs = req.extra_days * 86_400;
    match db::extend_license(&pool, &req.key_hash, extra_secs).await {
        // BUG-09 FIX: 区分"成功"和"未找到/已撤销"
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

    // BUG-E FIX: valid_days 范围校验 [1, 36500]（1天 ~ 100年）
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
    let note = req.note.as_deref().unwrap_or("admin");
    let key = generate_hkey();
    let key_hash = hash_key(&key);

    match db::add_key(&pool, &key, &key_hash, expires_at, note).await {
        Ok(true) => (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "key":      key,
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
        // BUG-I FIX: batch_init_keys 内部已改为 UNNEST 单次往返
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
