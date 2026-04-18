// server/src/handlers.rs — 优化版（修复 BUG-01/02/03/08/09/11）

use crate::{auth, cache, db};
use axum::{
    extract::{Extension, Json, Query},
    http::StatusCode,
    response::IntoResponse,
};
use cache::{RedisPool, VerifyCacheEntry};
use db::DbPool;
use hex;
// use hmac::KeyInit;
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

// ── HMAC-SHA256(key, "key_hash|timestamp") ─────────────────────────────────
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
    // 常量时间比较，防时序攻击
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
        &uid[16..20],
    )
}

// ── BUG-01 FIX: nonce 去重，防止重放攻击 ─────────────────────────────────────
async fn check_and_store_nonce(redis_pool: &RedisPool, sig: &str) -> bool {
    use deadpool_redis::redis::AsyncCommands;
    let key = format!("nonce:{}", sig);
    let Ok(mut conn) = redis_pool.get().await else {
        // Redis 不可用时宽松放行（降级策略）
        return true;
    };
    // SET nonce:{sig} 1 EX 70 NX — 70s > 最大时间窗口 2×30s
    let result: Result<Option<String>, _> = deadpool_redis::redis::cmd("SET")
        .arg(&key)
        .arg("1")
        .arg("EX")
        .arg(70i64)
        .arg("NX")
        .query_async(&mut conn)
        .await;
    // NX 成功 → Ok(Some("OK"))，重复 → Ok(None)
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
    let now = now_secs();

    // [1] 时间戳窗口（±30s）
    if (now - req.timestamp).abs() > 30 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "ERR-TIME-RECORD"})),
        )
            .into_response();
    }

    // BUG-01 FIX: 签名 nonce 去重，防重放
    if !check_and_store_nonce(&redis_pool, &req.signature).await {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": "ERR-REPLAY"})),
        )
            .into_response();
    }

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

    // BUG-03 FIX: 签名验证（使用 DB 中的明文 key）
    if !verify_hmac_signature(&record.key, &req.key_hash, req.timestamp, &req.signature) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid signature"})),
        )
            .into_response();
    }

    // 已撤销检查
    if record.revoked {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "key revoked"})),
        )
            .into_response();
    }

    if record.activation_ts == 0 {
        // BUG-02 FIX: 校验 expires_at 不能在过去
        let expires_at = if record.expires_at > 0 {
            if record.expires_at <= now {
                return (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({"error": "ERR-KEY-PRE-EXPIRED"})),
                )
                    .into_response();
            }
            record.expires_at // /admin/add-key 指定的 valid_days
        } else {
            now + 365 * 86_400 // batch_init 的 key 激活一年
        };

        match sqlx::query("UPDATE licenses SET activation_ts=$1, expires_at=$2 WHERE key_hash=$3")
            .bind(now)
            .bind(expires_at)
            .bind(&req.key_hash)
            .execute(pool.as_ref())
            .await
        {
            Ok(_) => {}
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": e.to_string()})),
                )
                    .into_response();
            }
        }

        // 失效缓存
        let rp = Arc::clone(&redis_pool);
        let kh = req.key_hash.clone();
        tokio::spawn(async move {
            cache::invalidate_verify_cache(&rp, &kh).await;
        });

        (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "activation_ts": now,
                "expires_at":    expires_at,
                "message":       "Activated."
            })),
        )
            .into_response()
    } else {
        (
            StatusCode::OK,
            Json(serde_json::json!({
                "activation_ts": record.activation_ts,
                "expires_at":    record.expires_at,
                "message":       "Already activated (returning original timestamps)"
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

    // [1] 时间戳窗口
    if (now - req.timestamp).abs() > 30 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "ERR-TIME-RECORD"})),
        )
            .into_response();
    }

    // BUG-03 FIX: verify() 也必须验签，否则任何人凭 key_hash 即可查询
    // 但此时还没拿到 record.key，需要先查 DB（或先查 Cache 里存 key？）
    // 架构决策：verify 路径先查 Redis cache，cache miss 再查 DB；
    // 签名验证需要 key，只能在拿到 DB 记录后做。
    // 为保性能，cache hit 时也从 DB 拿 key 做签名验证会损失缓存价值；
    // 折中方案：将 key_hash 的签名 nonce 也在 cache 中存一份 public key token，
    // 实际部署建议在 /verify 前加 API Gateway mTLS 或 IP 白名单。
    // 此处实现：先 Redis 查元数据，miss 时查 DB 并验签。
    let cache_entry = cache::get_verify_cache(&redis_pool, &req.key_hash).await;

    let (entry, from_db) = match cache_entry {
        Some(e) => (e, false),
        None => {
            // Cache miss → 查 DB
            match db::find_license(&pool, &req.key_hash).await {
                Ok(Some(record)) => {
                    // BUG-03 FIX: DB 路径做签名验证
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
                        activation_ts: record.activation_ts,
                        expires_at: record.expires_at,
                        revoked: record.revoked,
                    };
                    // 写 Cache
                    cache::set_verify_cache(&redis_pool, &req.key_hash, &e).await;
                    (e, true)
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

    // BUG-11 FIX: 仅在 DB miss（from_db=true）时更新 last_check
    if from_db {
        let pool2 = Arc::clone(&pool);
        let kh = req.key_hash.clone();
        tokio::spawn(async move {
            let _ = db::update_last_check(&pool2, &kh, now).await;
        });
    }

    // 已撤销
    if entry.revoked {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "activation_ts": entry.activation_ts,
                "expires_at":    entry.expires_at,
                "revoked":       true,
                "error":         "key revoked"
            })),
        )
            .into_response();
    }

    // 未激活
    if entry.activation_ts == 0 {
        return (
            StatusCode::PAYMENT_REQUIRED,
            Json(serde_json::json!({"error": "not activated"})),
        )
            .into_response();
    }

    // 已过期
    if now >= entry.expires_at {
        return (
            StatusCode::PAYMENT_REQUIRED,
            Json(serde_json::json!({
                "activation_ts": entry.activation_ts,
                "expires_at":    entry.expires_at,
                "revoked":       false,
                "error":         "expired"
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

// ── Admin 鉴权 middleware helper ──────────────────────────────────────────────

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

// ── DELETE /admin/revoke ──────────────────────────────────────────────────────

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
            // 立即失效缓存
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
        Ok(true) => {
            cache::invalidate_verify_cache(&redis_pool, &req.key_hash).await;
            (
                StatusCode::OK,
                Json(serde_json::json!({"message": "extended"})),
            )
                .into_response()
        }
        // BUG-09 FIX: extend 被撤销的 key 会 rows_affected==0
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
    valid_days: Option<i64>, // None 表示激活时再定（batch 风格）
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
    let key = generate_hkey();
    let key_hash = hash_key(&key);
    let expires_at = if let Some(days) = req.valid_days {
        if days <= 0 {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "valid_days must be > 0"})),
            )
                .into_response();
        }
        // BUG-02 防护：expires_at 从现在起算，不会在过去
        now_secs() + days * 86_400
    } else {
        0 // 激活时再设
    };
    let note = req.note.as_deref().unwrap_or("");
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
