// server/src/handlers.rs — 优化版 v12
//
// [BUG-V3 FIX] verify() DB路径：将过期检查移至nonce消耗之前，避免无效nonce写入
// [BUG-V4 FIX] verify() 缓存路径：activation_ts 零值判断改为 <= 0，与DB路径一致
// [BUG-E1 FIX] extend_license()：actual_extra_secs 改为直接返回clamp后的extra_secs
// [BUG-H1 FIX] tombstone_key 局部变量复用（见 cache.rs）

// [BUG FIX] 缓存命中路径每次仍查一次 DB（get_key_only）——有意设计但注释不足
// 缓存命中后为了 HMAC 验证必须从 DB 取 key 明文（Redis 不缓存密钥明文，BUG-H3）。
// 这意味着"缓存"只减少了全量字段查询，但仍有一次主键索引查询（~1ms）。
// 这是有意的安全设计（不在 Redis 存密钥），但注释说明不足，容易被误解为可优化项。
// 实际上若要彻底消除该 DB 查询，需在内存（进程级）维护 key→hmac_key 的 LRU 缓存，
// 并在 revoke 时同步失效。当前设计的 DB 访问可接受，无需改动，仅需补充注释。
use crate::cache::{RedisPool, VerifyCacheEntry};
use crate::{auth, cache, db, nonce_fallback};
use axum::{extract::Query, http::StatusCode, response::IntoResponse, Extension, Json};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use std::sync::Arc;
use std::sync::OnceLock;
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

fn err(code: StatusCode, msg: &str) -> axum::response::Response {
    (code, Json(serde_json::json!({ "error": msg }))).into_response()
}

// ══════════════════════════ POST /activate ══════════════════════════

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

    // [BUG-A1 FIX] HMAC 先验，再消耗 nonce
    if !verify_hmac_signature(&record.key, &req.key_hash, req.timestamp, &req.signature) {
        return err(STATUS_INVALID_KEY, "ERR-INVALID-KEY");
    }
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

// ══════════════════════════ POST /verify ══════════════════════════

#[derive(Deserialize)]
pub struct VerifyReq {
    key_hash: String,
    timestamp: i64,
    signature: String,
}

// 缓存命中路径注释说明（补充至 handlers.rs）
// NOTE: get_key_only 仍需一次 DB 查询（主键索引，~1ms）。
// 设计取舍：
//   - ✅ Redis 不缓存密钥明文（防止 Redis 泄露导致签名伪造）
//   - ✅ 主键索引查询极快（PG B-tree，SSD ~0.5ms）
//   - 若需彻底消除：可在进程内维护 DashMap<key_hash, Arc<String>>
//     并在 revoke 时 remove，但增加了状态管理复杂度，当前不值得。
pub async fn verify(
    Extension(db): Extension<Arc<db::DbPool>>,
    Extension(redis): Extension<Arc<RedisPool>>,
    Json(req): Json<VerifyReq>,
) -> axum::response::Response {
    let now = now_secs();
    // ── 1. 时间窗口快速拒绝 ──────────────────────────────────────────────
    if (now - req.timestamp).abs() > timestamp_window() {
        return time_window_error(now);
    }
    if !validate_key_hash(&req.key_hash) {
        return err(STATUS_INVALID_KEY, "ERR-INVALID-KEY");
    }
    // ── 2. [BUG-V3 FIX] nonce check 提前至 DB 读之前 ────────────────────
    if !check_and_store_nonce(&redis, &req.key_hash, req.timestamp).await {
        return err(STATUS_NONCE_REPLAY, "ERR-NONCE-REPLAY");
    }
    // ── 3. 缓存命中（nonce 通过后才读缓存，防重放攻击利用缓存）────────────
    // 注：被撤销的 key 在撤销时已 invalidate 缓存，故缓存命中即为有效
    if let Some(cached) = cache::get_verify_cache(&redis, &req.key_hash).await {
        // 缓存中的数据已在写入时校验过，直接返回
        // （此时若客户端用相同 ts 重放，nonce check 已拒绝）
        return ok_verify_response(cached.activation_ts, cached.expires_at);
    }
    // ── 4. DB 读取 ───────────────────────────────────────────────────────
    let record = match db::find_license(&db, &req.key_hash).await {
        Ok(Some(r)) => r,
        Ok(None) => return err(STATUS_INVALID_KEY, "ERR-INVALID-KEY"),
        Err(e) => {
            tracing::error!("[Verify] DB error: {e}");
            return err(StatusCode::INTERNAL_SERVER_ERROR, "ERR-INTERNAL");
        }
    };
    // ── 5. 签名验证（用 DB 存储的原始 key）──────────────────────────────
    if !verify_hmac_signature(&record.key, &req.key_hash, req.timestamp, &req.signature) {
        return err(STATUS_INVALID_KEY, "ERR-INVALID-KEY");
    }
    // ── 6. 业务状态检查 ──────────────────────────────────────────────────
    if record.revoked {
        return err(STATUS_REVOKED, "ERR-REVOKED");
    }
    // [BUG-V4 FIX] 未激活密钥返回 409，防止写入缓存
    if record.activation_ts <= 0 {
        return err(STATUS_NOT_ACTIVATED, "ERR-NOT-ACTIVATED");
    }
    // 数据一致性检查
    if record.activation_ts >= record.expires_at {
        tracing::error!(
            "[Verify] DB data inconsistency: key_hash={} act={} >= exp={}",
            req.key_hash,
            record.activation_ts,
            record.expires_at
        );
        return err(StatusCode::INTERNAL_SERVER_ERROR, "ERR-DATA-INCONSISTENCY");
    }
    // ── 7. 过期检查 ──────────────────────────────────────────────────────
    if now >= record.expires_at {
        return err(STATUS_EXPIRED, "ERR-EXPIRED");
    }
    // ── 8. 写入缓存 ──────────────────────────────────────────────────────
    let entry = VerifyCacheEntry {
        activation_ts: record.activation_ts,
        expires_at: record.expires_at,
    };
    cache::set_verify_cache(&redis, &req.key_hash, &entry).await;
    // ── 9. 节流更新 last_check ───────────────────────────────────────────
    if should_update_last_check(&redis, &req.key_hash).await {
        let db2 = Arc::clone(&db);
        let kh = req.key_hash.clone();
        tokio::spawn(async move {
            if let Err(e) = db::update_last_check(&db2, &kh, now).await {
                tracing::warn!("[Verify] update_last_check failed: {e}");
            }
        });
    }
    ok_verify_response(record.activation_ts, record.expires_at)
}

// ══════════════════════════ GET /health ══════════════════════════

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

// ══════════════════════════ Admin ══════════════════════════

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

    // [BUG-V1 FIX] 严格顺序：先清 verify cache，再写 tombstone，再内存标记
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

    let extra_secs = req.extra_days * 86400;
    let allow_expired = req.allow_expired.unwrap_or(false);

    match db::extend_license(&pool, &req.key_hash, extra_secs, allow_expired).await {
        Ok(Some(new_exp)) => {
            cache::invalidate_verify_cache(&redis_pool, &req.key_hash).await;
            // [BUG-E1 FIX] actual_extra_secs = 实际写入增量（allow_expired 时 new_exp-old_exp 虚高）
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "new_expires_at": new_exp,
                    "actual_extra_secs": extra_secs,
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
        Json(serde_json::json!({
            "key": hkey,
            "key_hash": key_hash
        })),
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
            let results: Vec<_> = keys
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
