// server/src/handlers.rs — 最终优化版（完整）
// 修复: BUG-01(replay) BUG-02(expires=0顺序) BUG-03(无验签) BUG-08(last_check NULL)
//       BUG-09(extend静默失败) BUG-A(激活前校验expires) BUG-B(cache验签)
//       BUG-C(nonce降级) BUG-D(last_check节流) BUG-E(valid_days校验)
//       BUG-G(时间窗口可配+server_time) BUG-H(revoke改POST)
// 新增修复: BUG-NEW-1(valid_days代码截断) BUG-NEW-2(并发激活无行数检查)
//           BUG-NEW-3(nonce EX=70s vs 窗口300s) BUG-NEW-5(撤销响应信息泄露)
//           BUG-NEW-10(内存降级nonce多实例问题→fail-closed)

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

/// BUG-G FIX: 时间窗口从环境变量读取（默认 300s）
fn timestamp_window() -> i64 {
    std::env::var("TIMESTAMP_WINDOW_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300)
}

/// BUG-NEW-3 FIX: nonce TTL 与时间窗口对齐（+30s 安全余量），防止窗口内重放
fn nonce_ttl() -> i64 {
    // 必须 >= timestamp_window()，否则时间窗口内 nonce 过期后可被重放
    timestamp_window() + 30
}

/// BUG-01 FIX: nonce 去重（Redis NX 原子操作）
/// BUG-C  FIX: Redis 宕机 → fail-closed（BUG-NEW-10 FIX: 多实例下内存集不安全）
/// BUG-NEW-3 FIX: EX 使用 nonce_ttl()，不再写死 70s
async fn check_and_store_nonce(redis_pool: &RedisPool, sig: &str) -> bool {
    let key = format!("nonce:{}", sig);
    match redis_pool.get().await {
        Ok(mut conn) => {
            let result: Result<Option<String>, _> = deadpool_redis::redis::cmd("SET")
                .arg(&key)
                .arg("1")
                .arg("EX")
                .arg(nonce_ttl()) // BUG-NEW-3 FIX: 动态 TTL，与时间窗口严格对齐
                .arg("NX") // 原子"不存在才写"
                .query_async(&mut conn)
                .await;
            matches!(result, Ok(Some(_)))
        }
        Err(e) => {
            // BUG-NEW-10 FIX: Redis 不可用时 fail-closed（拒绝请求）
            // 理由：内存降级集合在多实例部署下无法共享，重放防护失效
            // 运维侧应通过 /health 监控 Redis 状态并及时恢复
            tracing::error!(
                "[Nonce] Redis 不可用 ({})，fail-closed 拒绝请求（防多实例重放）",
                e
            );
            false
        }
    }
}

/// BUG-D FIX: last_check 限流写入（60s 内最多写一次 DB）
async fn should_update_last_check(redis_pool: &RedisPool, key_hash: &str) -> bool {
    let throttle_key = format!("lc_throttle:{}", key_hash);
    let Ok(mut conn) = redis_pool.get().await else {
        return true; // Redis 不可用时不限流（last_check 非关键路径）
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
    let now = now_secs();

    // [1] 时间戳窗口（BUG-G FIX: 可配置，返回 server_time）
    if (now - req.timestamp).abs() > timestamp_window() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "ERR-TIME-RECORD", "server_time": now})),
        )
            .into_response();
    }

    // [2] BUG-01 FIX: nonce 去重（BUG-NEW-10 FIX: fail-closed）
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

    // [4] BUG-03 FIX: 签名验证
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
            record.expires_at
        } else if record.expires_at > 0 {
            return (
                StatusCode::GONE,
                Json(serde_json::json!({
                    "error": "key has a pre-set expiry that is already in the past; use /admin/extend first"
                })),
            )
                .into_response();
        } else {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({
                    "error": "key has no expiry configured; use /admin/add-key with valid_days or /admin/extend"
                })),
            )
                .into_response();
        };

        // BUG-NEW-2 FIX: activate_license 现在返回 Result<bool>，检查是否真正激活成功
        match db::activate_license(&pool, &req.key_hash, now, expires_at).await {
            Ok(true) => {
                // 激活成功：主动失效 Redis 缓存
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
            }
            Ok(false) => {
                // BUG-NEW-2 FIX: 并发竞争——另一请求已抢先激活
                // 查询 DB 中真实记录，返回实际值（保证客户端缓存与 DB 一致）
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
        // 已激活：幂等返回 DB 中真实时间戳（不是本次 now）
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

// ── POST /verify ───────────────────────────────────────────────────────────
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

    // [2] BUG-01 + BUG-NEW-3 FIX: nonce 去重（TTL 与时间窗口对齐）
    if !check_and_store_nonce(&redis_pool, &req.signature).await {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": "ERR-REPLAY"})),
        )
            .into_response();
    }

    // [3] 查 Cache 或 DB
    // BUG-NEW-4 FIX: cache 不再存 key，cache-hit 时仍需从 DB 取 key 做验签
    // BUG-B FIX: 无论 cache-hit 还是 DB-hit，都必须验签
    let entry = match cache::get_verify_cache(&redis_pool, &req.key_hash).await {
        Some(cached_entry) => {
            // Cache 命中：仍需从 DB 取 key 验签（cache 不存原始凭证）
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
            // BUG-B FIX: cache-hit 时也验签
            if !verify_hmac_signature(&record.key, &req.key_hash, req.timestamp, &req.signature) {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({"error": "invalid signature"})),
                )
                    .into_response();
            }
            cached_entry
        }
        None => {
            // Cache 未命中：从 DB 读取
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
                    // BUG-NEW-4 FIX: 缓存条目不含 key 字段
                    let e = VerifyCacheEntry {
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
    // BUG-NEW-5 FIX: 不返回 activation_ts/expires_at，防止信息泄露
    if entry.revoked {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "revoked": true,
                "error": "key revoked"
                // 不返回时间戳，防止信息泄露（BUG-NEW-5 FIX）
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

// ── GET /health ────────────────────────────────────────────────────────────
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

// ── GET /admin/licenses ────────────────────────────────────────────────────
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

// ── POST /admin/revoke（BUG-H FIX: 由 DELETE 改 POST）─────────────────────
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

// ── POST /admin/extend ─────────────────────────────────────────────────────
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

// ── POST /admin/add-key ────────────────────────────────────────────────────
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

    // BUG-E FIX + BUG-NEW-1 FIX: valid_days 范围校验 [1, 36500]
    // 原代码在 GitHub raw 中被截断，导致校验逻辑无法执行
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

// ── POST /admin/batch-init ─────────────────────────────────────────────────
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
