// server/src/handlers.rs — 优化版 v11
//
// [BUG-V1 FIX] is_revoked() 返回 true 后立即 invalidate verify cache
// [BUG-V2 FIX] 缓存命中路径：HMAC 验证 → nonce 消耗（顺序修正）
// [BUG-A1 FIX] activate()：HMAC 验证移至 nonce 消耗之前
// [BUG-C1 FIX] tombstone TTL 查询失败时用 MIN_MEMORY_REVOKE_TTL 而非最大值（见 cache.rs）
// [BUG-D1 FIX] extend 响应返回真实延长秒数
// [OPT-1 NOTE] throttle_key 全局唯一，两路径不重复写，补充注释

use crate::cache::{RedisPool, VerifyCacheEntry};
use crate::{auth, cache, db, nonce_fallback};
use axum::{extract::Query, http::StatusCode, response::IntoResponse, Extension, Json};
use hex;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

const STATUS_EXPIRED: StatusCode = StatusCode::GONE;
const STATUS_REVOKED: StatusCode = StatusCode::FORBIDDEN;
const STATUS_NOT_ACTIVATED: StatusCode = StatusCode::CONFLICT;
const STATUS_NONCE_REPLAY: StatusCode = StatusCode::CONFLICT;
const STATUS_INVALID_KEY: StatusCode = StatusCode::FORBIDDEN;

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
    db::hash_key(key)
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
    let expected = hex::encode(mac.finalize().into_bytes());
    if expected.len() != sig.len() {
        return false;
    }
    expected.as_bytes().ct_eq(sig.as_bytes()).into()
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

async fn check_and_store_nonce(pool: &RedisPool, key_hash: &str, ts: i64) -> bool {
    let key = format!("nonce:{}:{}", key_hash, ts);
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
            nonce_fallback::check_and_store(&key, nonce_ttl() as u64)
        }
    }
}

async fn should_update_last_check(pool: &RedisPool, key_hash: &str) -> bool {
    // NOTE: throttle_key 全局唯一（lc:v1:throttle:{key_hash}），缓存和 DB 两条路径
    // 共享同一个节流 key，60s 内对同一 key_hash 只允许一次通过，不存在重复写问题。
    let throttle_key = cache::throttle_key(key_hash);
    let Ok(mut conn) = pool.get().await else {
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

fn ok_verify_response(activation_ts: i64, expires_at: i64) -> axum::response::Response {
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

fn time_window_error(now: i64) -> axum::response::Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({
            "error": "ERR-TIME-RECORD",
            "server_time": now
        })),
    )
        .into_response()
}

// ═══════════════════════════════ POST /activate ═══════════════════════════════

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
        return err(StatusCode::BAD_REQUEST, "invalid key_hash format");
    }
    let now = now_secs();
    if (now - req.timestamp).abs() > timestamp_window() {
        return time_window_error(now);
    }

    let record = match db::find_license(&pool, &req.key_hash).await {
        Ok(Some(r)) => r,
        Ok(None) => return err(STATUS_INVALID_KEY, "ERR-INVALID-KEY"),
        Err(e) => {
            tracing::error!("[Activate] DB error: {}", e);
            return err(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
        }
    };

    if record.revoked {
        return err(STATUS_REVOKED, "ERR-REVOKED");
    }
    if record.activation_ts > 0 {
        return err(STATUS_NOT_ACTIVATED, "ERR-ALREADY-ACTIVATED");
    }

    // [BUG-A1 FIX] HMAC 验证移至 nonce 消耗之前，防止签名无效请求耗尽 nonce 槽
    if !verify_hmac_signature(&record.key, &req.key_hash, req.timestamp, &req.signature) {
        return err(STATUS_INVALID_KEY, "ERR-INVALID-KEY");
    }

    // ✅ 签名合法后才消耗 nonce
    if !check_and_store_nonce(&redis_pool, &req.key_hash, req.timestamp).await {
        return err(STATUS_NONCE_REPLAY, "ERR-NONCE-REPLAY");
    }

    let activation_ts = now;
    let default_days: i64 = std::env::var("DEFAULT_LICENSE_DAYS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(365);
    let extra_secs = default_days
        .checked_mul(86400)
        .unwrap_or(db::MAX_EXTEND_SECS)
        .clamp(1, db::MAX_EXTEND_SECS);
    let expires_at = activation_ts + extra_secs;

    match db::activate_license(&pool, &req.key_hash, activation_ts, expires_at).await {
        Ok(true) => {
            tracing::info!("[Activate] activated key_hash={}...", &req.key_hash[..8]);
            ok_verify_response(activation_ts, expires_at)
        }
        Ok(false) => {
            tracing::warn!("[Activate] concurrent activation");
            err(STATUS_NOT_ACTIVATED, "ERR-ALREADY-ACTIVATED")
        }
        Err(e) => {
            tracing::error!("[Activate] DB write: {}", e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
        }
    }
}

// ═══════════════════════════════ POST /verify ═══════════════════════════════

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
        return time_window_error(now);
    }

    // [BUG-V1 FIX] revoke 检查后立即清 verify cache，防止30s窗口内残留缓存被命中
    if cache::is_revoked(&redis_pool, &req.key_hash).await {
        cache::invalidate_verify_cache(&redis_pool, &req.key_hash).await; // ✅ 先清再返回
        return err(STATUS_REVOKED, "ERR-REVOKED");
    }

    // 缓存命中路径
    if let Some(entry) = cache::get_verify_cache(&redis_pool, &req.key_hash).await {
        // [BUG-V2 FIX] 缓存数据一致性检查
        if entry.activation_ts <= 0 || entry.activation_ts >= entry.expires_at {
            cache::invalidate_verify_cache(&redis_pool, &req.key_hash).await;
            tracing::error!(
                "[Verify] cache integrity violation: act={} >= exp={}",
                entry.activation_ts,
                entry.expires_at
            );
            return err(STATUS_NOT_ACTIVATED, "ERR-NOT-ACTIVATED");
        }

        if now >= entry.expires_at {
            cache::invalidate_verify_cache(&redis_pool, &req.key_hash).await;
            return err(STATUS_EXPIRED, "ERR-EXPIRED");
        }

        // HMAC 验证必须用 DB 中的 key（Redis 不缓存明文）
        // NOTE: get_key_only 仍需一次 DB 查询（主键 B-tree 索引，~1ms）。
        // 这是有意的安全设计：不在 Redis 缓存密钥明文，防止 Redis 泄露导致签名伪造。
        let db_key = match db::get_key_only(&pool, &req.key_hash).await {
            Ok(Some(k)) => k,
            Ok(None) => return err(STATUS_INVALID_KEY, "ERR-INVALID-KEY"),
            Err(e) => {
                tracing::error!("[Verify] DB key fetch: {}", e);
                return err(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
            }
        };

        // [BUG-V2 FIX] HMAC 先验，通过后才消耗 nonce
        if !verify_hmac_signature(&db_key, &req.key_hash, req.timestamp, &req.signature) {
            return err(STATUS_INVALID_KEY, "ERR-INVALID-KEY");
        }
        // ✅ 签名合法后才消耗 nonce
        if !check_and_store_nonce(&redis_pool, &req.key_hash, req.timestamp).await {
            return err(STATUS_NONCE_REPLAY, "ERR-NONCE-REPLAY");
        }

        if should_update_last_check(&redis_pool, &req.key_hash).await {
            let pool_c = pool.clone();
            let kh = req.key_hash.clone();
            tokio::spawn(async move {
                let _ = db::update_last_check(&pool_c, &kh, now).await;
            });
        }
        return ok_verify_response(entry.activation_ts, entry.expires_at);
    }

    // DB 路径
    let record = match db::find_license(&pool, &req.key_hash).await {
        Ok(Some(r)) => r,
        Ok(None) => return err(STATUS_INVALID_KEY, "ERR-INVALID-KEY"),
        Err(e) => {
            tracing::error!("[Verify] DB error: {}", e);
            return err(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
        }
    };

    if record.revoked {
        cache::mark_revoked_in_memory(&req.key_hash, record.expires_at);
        return err(STATUS_REVOKED, "ERR-REVOKED");
    }
    if record.activation_ts == 0 {
        return err(STATUS_NOT_ACTIVATED, "ERR-NOT-ACTIVATED");
    }

    // 数据一致性防御
    if record.activation_ts >= record.expires_at {
        tracing::error!(
            "[Verify] DB integrity violation: act={} >= exp={}",
            record.activation_ts,
            record.expires_at
        );
        return err(STATUS_NOT_ACTIVATED, "ERR-NOT-ACTIVATED");
    }

    // ✅ HMAC 先验，通过后才消耗 nonce
    if !verify_hmac_signature(&record.key, &req.key_hash, req.timestamp, &req.signature) {
        return err(STATUS_INVALID_KEY, "ERR-INVALID-KEY");
    }
    if !check_and_store_nonce(&redis_pool, &req.key_hash, req.timestamp).await {
        return err(STATUS_NONCE_REPLAY, "ERR-NONCE-REPLAY");
    }

    if now >= record.expires_at {
        return err(STATUS_EXPIRED, "ERR-EXPIRED");
    }

    cache::set_verify_cache(
        &redis_pool,
        &req.key_hash,
        &VerifyCacheEntry {
            activation_ts: record.activation_ts,
            expires_at: record.expires_at,
        },
    )
    .await;

    if should_update_last_check(&redis_pool, &req.key_hash).await {
        let pool_c = pool.clone();
        let kh = req.key_hash.clone();
        tokio::spawn(async move {
            let _ = db::update_last_check(&pool_c, &kh, now).await;
        });
    }

    ok_verify_response(record.activation_ts, record.expires_at)
}

// ═══════════════════════════════ GET /health ═══════════════════════════════

pub async fn health(
    Extension(pool): Extension<Arc<db::DbPool>>,
    Extension(redis_pool): Extension<Arc<RedisPool>>,
) -> impl IntoResponse {
    let db_ok = sqlx::query("SELECT 1").execute(pool.as_ref()).await.is_ok();
    let redis_ok = match redis_pool.get().await {
        Ok(mut c) => deadpool_redis::redis::cmd("PING")
            .query_async::<_, String>(&mut c)
            .await
            .is_ok(),
        Err(_) => false,
    };
    let (nonce_total, nonce_rejected, nonce_map_size) = nonce_fallback::get_nonce_stats();
    let (cache_hits, cache_misses) = cache::get_cache_stats();
    let status = if db_ok && redis_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(serde_json::json!({
            "status": if db_ok && redis_ok { "ok" } else { "degraded" },
            "db": db_ok,
            "redis": redis_ok,
            "nonce_stats": {
                "total_checks": nonce_total,
                "rejected": nonce_rejected,
                "map_size": nonce_map_size
            },
            "cache_stats": {
                "hits": cache_hits,
                "misses": cache_misses
            },
        })),
    )
        .into_response()
}

fn err(code: StatusCode, msg: &str) -> axum::response::Response {
    (code, Json(serde_json::json!({ "error": msg }))).into_response()
}

// ═══════════════════════════════ Admin ═══════════════════════════════

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
    match db::revoke_license(&pool, &req.key_hash, reason).await {
        Ok(false) => return err(StatusCode::NOT_FOUND, "key not found"),
        Ok(true) => {}
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
    // [BUG-V1 FIX] 严格顺序：先清 verify cache，再设 tombstone，再内存标记
    cache::invalidate_verify_cache(&redis_pool, &req.key_hash).await;
    cache::set_revoke_tombstone(&redis_pool, &req.key_hash).await;
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
    if req.extra_days < 1 {
        return err(StatusCode::BAD_REQUEST, "extra_days must be >= 1");
    }
    if req.extra_days > db::MAX_EXTEND_DAYS {
        return err(
            StatusCode::BAD_REQUEST,
            &format!("extra_days must be <= {}", db::MAX_EXTEND_DAYS),
        );
    }
    let allow_expired = req.allow_expired.unwrap_or(false);
    let extra_secs = req
        .extra_days
        .saturating_mul(86400)
        .clamp(1, db::MAX_EXTEND_SECS);

    // 先查旧 expires_at（用于计算实际延长量）
    let old_exp = match db::find_license(&pool, &req.key_hash).await {
        Ok(Some(r)) => r.expires_at,
        Ok(None) => return err(StatusCode::NOT_FOUND, "license not found"),
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };

    match db::extend_license(&pool, &req.key_hash, extra_secs, allow_expired).await {
        Ok(Some(new_exp)) => {
            cache::invalidate_verify_cache(&redis_pool, &req.key_hash).await;
            // [BUG-D1 FIX] 返回实际延长秒数（DB clamp 后的真实差值）
            let actual_extra_secs = new_exp - old_exp;
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "new_expires_at": new_exp,
                    "actual_extra_secs": actual_extra_secs
                })),
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
    Extension(admin_token): Extension<Arc<String>>,
    Json(req): Json<BatchInitReq>,
) -> impl IntoResponse {
    if !auth::verify_admin_token(&req.token, &admin_token) {
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
            let results: Vec<serde_json::Value> = keys
                .iter()
                .map(|k| serde_json::json!({ "key": k, "key_hash": hash_key(k) }))
                .collect();
            tracing::info!("[Admin] batch_init: {} keys created", keys.len());
            Json(serde_json::json!({
                "ok": true,
                "count": keys.len(),
                "keys": results
            }))
            .into_response()
        }
        Err(e) => {
            tracing::error!("[Admin] batch_init error: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
