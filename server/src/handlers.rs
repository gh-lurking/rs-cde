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

// server/src/handlers.rs — 优化版 v13
//
// [OPT-1 FIX]  revoke 操作顺序：先写 tombstone 再删缓存（消除鉴权绕过窗口）
// [OPT-3 FIX]  进程内 key_cache 消除热路径 DB 查询
// [OPT-4 FIX]  now_secs() 防 panic + 防溢出
// [OPT-6 FIX]  verify_hmac_signature sig 长度上界防护
// 与 CLAUDE.md §3 「Surgical Changes」一致：仅修改必要行，不动其他逻辑

use crate::cache::{RedisPool, VerifyCacheEntry};
use crate::key_cache; // [OPT-3] 进程内 key 缓存
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

// HMAC-SHA256 输出固定 64 字节 hex，公开常量，不构成时序侧信道
const _HMAC_HEX_LEN: usize = 64;
// sig 长度上界：防止超长签名导致 ct_eq CPU 耗尽 [OPT-6]
const SIG_MAX_LEN: usize = 256;

static SERVER_ID: OnceLock<String> = OnceLock::new();

fn get_server_id() -> &'static str {
    SERVER_ID.get_or_init(|| {
        std::env::var("SERVER_ID").unwrap_or_else(|_| "license-server-v1".to_string())
    })
}

// [OPT-4] 防 panic（时钟早于 UNIX_EPOCH）+ 防溢出（as i64 截断）
fn now_secs() -> i64 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    i64::try_from(secs).unwrap_or(i64::MAX)
}

fn hash_key(key: &str) -> String {
    db::hash_key(key)
}

fn validate_key_hash(key_hash: &str) -> bool {
    key_hash.len() == 64 && key_hash.chars().all(|c| c.is_ascii_hexdigit())
}

// [OPT-6] sig 长度上界防护 + 明确注释
fn verify_hmac_signature(key: &str, key_hash: &str, timestamp: i64, sig: &str) -> bool {
    if sig.len() > SIG_MAX_LEN {
        return false;
    }
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
            tracing::warn!("[Nonce] Redis unavailable ({}) using memory fallback", e);
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
        Ok(true) => ok_verify_response(activation_ts, expires_at),
        Ok(false) => err(STATUS_NOT_ACTIVATED, "ERR-ALREADY-ACTIVATED"),
        Err(e) => {
            tracing::error!("[Activate] DB write: {}", e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
        }
    }
}

#[derive(Deserialize)]
pub struct VerifyReq {
    key_hash: String,
    timestamp: i64,
    signature: String,
}

// NOTE: get_key_only 已由进程内 key_cache 替代，消除热路径 DB 查询 [OPT-3]
// 设计取舍：
// - ✅ key_cache 不持久化，进程重启后自动重建（首次 /verify 回源 DB）
// - ✅ revoke 时同步 remove，不存在失效窗口
// - ✅ 容量上限 KEY_CACHE_MAX=10000，LRU 淘汰最旧条目
pub async fn verify(
    Extension(db): Extension<Arc<db::DbPool>>,
    Extension(redis): Extension<Arc<RedisPool>>,
    Json(req): Json<VerifyReq>,
) -> axum::response::Response {
    let now = now_secs();

    // ── 基础校验（不消耗 nonce）
    if (now - req.timestamp).abs() > timestamp_window() {
        return time_window_error(now);
    }
    if !validate_key_hash(&req.key_hash) {
        return err(STATUS_INVALID_KEY, "ERR-INVALID-KEY");
    }

    // Revoke 快速检查
    if cache::is_revoked(&redis, &req.key_hash).await {
        return err(STATUS_REVOKED, "ERR-REVOKED");
    }

    // HMAC 验证
    let key = match key_cache::get_or_load(&req.key_hash, &db).await {
        Ok(Some(v)) => v,
        Ok(None) => return err(STATUS_INVALID_KEY, "ERR-INVALID-KEY"),
        Err(e) => {
            tracing::error!("[Verify] key_cache DB error: {e}");
            return err(StatusCode::INTERNAL_SERVER_ERROR, "ERR-INTERNAL");
        }
    };
    if !verify_hmac_signature(&key, &req.key_hash, req.timestamp, &req.signature) {
        return err(STATUS_INVALID_KEY, "ERR-INVALID-KEY");
    }

    // ── [BUG-EXP-1 FIX] 缓存路径：先做过期检查，确认有效后再消耗 nonce ──
    if let Some(cached) = cache::get_verify_cache(&redis, &req.key_hash).await {
        if cached.activation_ts <= 0
            || cached.expires_at <= 0
            || cached.activation_ts >= cached.expires_at
        {
            tracing::warn!("[Verify] invalid cached entry, fallback to DB path");
            cache::invalidate_verify_cache(&redis, &req.key_hash).await;
            // fall through to DB path
        } else if now >= cached.expires_at {
            // [BUG-EXP-1 FIX] 过期直接返回，不消耗 nonce
            cache::invalidate_verify_cache(&redis, &req.key_hash).await;
            return err(STATUS_EXPIRED, "ERR-EXPIRED");
        } else {
            // 确认未过期：此时才消耗 nonce
            if !check_and_store_nonce(&redis, &req.key_hash, req.timestamp).await {
                return err(STATUS_NONCE_REPLAY, "ERR-NONCE-REPLAY");
            }
            // [BUG-CACHE-1 FIX] 缓存命中路径也更新 last_check
            if should_update_last_check(&redis, &req.key_hash).await {
                let db2 = Arc::clone(&db);
                let kh = req.key_hash.clone();
                tokio::spawn(async move {
                    if let Err(e) = db::update_last_check(&db2, &kh, now).await {
                        tracing::warn!("[Verify] cache-hit update_last_check failed: {e}");
                    }
                });
            }
            return ok_verify_response(cached.activation_ts, cached.expires_at);
        }
    }

    // ── [BUG-EXP-2 FIX] DB 路径：先查 DB + 过期校验，确认有效后再消耗 nonce ──
    let record = match db::find_license(&db, &req.key_hash).await {
        Ok(Some(r)) => r,
        Ok(None) => return err(STATUS_INVALID_KEY, "ERR-INVALID-KEY"),
        Err(e) => {
            tracing::error!("[Verify] DB error: {e}");
            return err(StatusCode::INTERNAL_SERVER_ERROR, "ERR-INTERNAL");
        }
    };

    if record.revoked {
        return err(STATUS_REVOKED, "ERR-REVOKED");
    }
    if record.activation_ts <= 0 {
        return err(STATUS_NOT_ACTIVATED, "ERR-NOT-ACTIVATED");
    }
    if record.activation_ts >= record.expires_at {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "ERR-DATA-INCONSISTENCY");
    }
    // [BUG-EXP-2 FIX] 过期检查在 nonce 消耗之前
    if now >= record.expires_at {
        return err(STATUS_EXPIRED, "ERR-EXPIRED");
    }

    // DB 路径确认有效：此时才消耗 nonce
    if !check_and_store_nonce(&redis, &req.key_hash, req.timestamp).await {
        return err(STATUS_NONCE_REPLAY, "ERR-NONCE-REPLAY");
    }

    let entry = VerifyCacheEntry {
        activation_ts: record.activation_ts,
        expires_at: record.expires_at,
    };
    cache::set_verify_cache(&redis, &req.key_hash, &entry).await;

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
    let key_cache_size = key_cache::cache_size();
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
            "key_cache_size": key_cache_size
        })),
    )
        .into_response()
}

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

    // [OPT-1] 正确顺序：先写 tombstone → 再删缓存 → 再内存标记
    // 原因：tombstone 是撤销持久化标记，必须先于缓存失效写入，
    // 否则存在「缓存已删但 tombstone 尚未写入」的竞态窗口。
    cache::set_revoke_tombstone(&redis_pool, &req.key_hash).await;
    cache::invalidate_verify_cache(&redis_pool, &req.key_hash).await;
    let tombstone_exp = now_secs() + 86400 * 30;
    cache::mark_revoked_in_memory(&req.key_hash, tombstone_exp);

    // [OPT-3] revoke 时同步从进程内 key_cache 移除，防止 HMAC 验证绕过
    key_cache::remove(&req.key_hash);

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
    // [OPT-5] count 上界从 10000 降至 5000，为未来加列保留 PG 参数余量
    // PG 协议参数上限 65535，当前 4列×5000=20000，安全余量充足
    if req.count == 0 || req.count > 5_000 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "count must be 1..5000"})),
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
