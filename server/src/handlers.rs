// server/src/handlers.rs — 请求处理逻辑
//
// ✅ 变更1: verify() — 新增 Redis 缓存层
//   缓存命中路径：Redis GET → 直接返回（零 DB IO）
//   缓存未命中：查 PostgreSQL → 异步写 Redis → 响应
//
// ✅ 变更2: update_last_check → tokio::spawn（不阻塞响应路径）
// ✅ 变更3: revoke/extend/activate 后主动 DEL Redis 缓存（强一致）

use axum::{
    extract::{Extension, Json, Query},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::{auth, cache, db};
use cache::{RedisPool, VerifyCacheEntry};
use db::DbPool;
// use db::{DbPool, LicenseRecord};

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
fn generate_hkey() -> String {
    let uid = Uuid::new_v4().simple().to_string().to_uppercase();
    format!(
        "{}-{}-{}-{}",
        &uid[12..16],
        &uid[0..4],
        &uid[4..8],
        &uid[8..12]
    )
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
    Extension(redis_pool): Extension<Arc<RedisPool>>, // ✅ 新增
    Json(req): Json<ActivateReq>,
) -> impl IntoResponse {
    let now = now_secs();
    let _ = &req.signature;
    if (now - req.timestamp).abs() > 60 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "ERR-TIME-RECORD"})),
        )
            .into_response();
    }

    match db::find_license(&pool, &req.key_hash).await {
        Ok(Some(record)) => {
            if record.activation_ts == 0 {
                let expires_at = now + 365 * 86400;
                sqlx::query(
                    "UPDATE licenses SET activation_ts=$1, expires_at=$2 WHERE key_hash=$3",
                )
                .bind(now)
                .bind(expires_at)
                .bind(&req.key_hash)
                .execute(pool.as_ref())
                .await
                .ok();

                // ✅ 激活后失效旧缓存
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
                        "message":       "Activated. Valid for one year"
                    })),
                )
                    .into_response()
            } else {
                (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "activation_ts": record.activation_ts,
                        "expires_at":    record.expires_at,
                        "message":       "Activated (Return origin time)"
                    })),
                )
                    .into_response()
            }
        }
        Ok(None) => (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "invalid key"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

// ── POST /verify ────────────────────────────────────────────────────────────
//
//  请求流程（带 Redis 缓存）：
//
//  客户端 POST /verify
//       │
//       ▼
//  [1] 时间戳校验（±60s）
//       │
//       ▼
//  [2] Redis GET verify:{key_hash}            ← ✅ 新增
//       │ 命中（TTL 内）                        缓存命中率通常 > 95%
//       ├─────────────────────────────────────► 直接返回 JSON（< 1 ms）
//       │ 未命中
//       ▼
//  [3] PostgreSQL SELECT WHERE key_hash = $1
//       │
//       ▼
//  [4] 检查吊销 / 自动吊销过期
//       │
//       ├── spawn → Redis SET verify:{key_hash} EX 30    ← ✅ 新增（异步）
//       │
//       ├── spawn → PostgreSQL UPDATE last_check          ← ✅ 已有（改 spawn）
//       │
//       ▼
//  [5] 返回 JSON 响应

#[derive(Deserialize)]
pub struct VerifyReq {
    key_hash: String,
    timestamp: i64,
    signature: String,
}

pub async fn verify(
    Extension(pool): Extension<Arc<DbPool>>,
    Extension(redis_pool): Extension<Arc<RedisPool>>, // ✅ 新增
    Json(req): Json<VerifyReq>,
) -> impl IntoResponse {
    let now = now_secs();
    let _ = &req.signature;

    if (now - req.timestamp).abs() > 60 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "ERR-TIME-RECORD"})),
        )
            .into_response();
    }

    // ── ✅ [2] 优先读取 Redis 缓存 ─────────────────────────────────────────
    if let Some(cached) = cache::get_verify_cache(&redis_pool, &req.key_hash).await {
        tracing::debug!("Cache Hit: {}...", &req.key_hash[..8]);

        // 缓存命中也异步更新 last_check（fire-and-forget）
        let pool_c = Arc::clone(&pool);
        let kh = req.key_hash.clone();
        tokio::spawn(async move {
            let _ = db::update_last_check(&pool_c, &kh, now).await;
        });

        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "activation_ts": cached.activation_ts,
                "expires_at":    cached.expires_at,
                "revoked":       cached.revoked,
            })),
        )
            .into_response();
    }

    // ── [3] Redis 未命中 → 查 PostgreSQL ─────────────────────────────────
    match db::find_license(&pool, &req.key_hash).await {
        Ok(Some(record)) => {
            let mut revoked = record.revoked;

            // ── [4] 检查自动吊销（过期）──────────────────────────────────
            if !revoked && record.expires_at > 0 && now >= record.expires_at {
                let pool_r = Arc::clone(&pool);
                let rp_r = Arc::clone(&redis_pool);
                let kh_r = req.key_hash.clone();
                tokio::spawn(async move {
                    let _ = db::revoke_license(&pool_r, &kh_r, "Invalid key, revoked").await;
                    cache::invalidate_verify_cache(&rp_r, &kh_r).await;
                });
                revoked = true;
            }

            let entry = VerifyCacheEntry {
                activation_ts: record.activation_ts,
                expires_at: record.expires_at,
                revoked,
            };

            // ── ✅ [5a] 异步写入 Redis 缓存 ──────────────────────────────
            let rp_w = Arc::clone(&redis_pool);
            let kh_w = req.key_hash.clone();
            let entry_w = entry.clone();
            tokio::spawn(async move {
                cache::set_verify_cache(&rp_w, &kh_w, &entry_w).await;
            });

            // ── [5b] 异步更新 last_check ─────────────────────────────────
            let pool_lc = Arc::clone(&pool);
            let kh_lc = req.key_hash.clone();
            tokio::spawn(async move {
                let _ = db::update_last_check(&pool_lc, &kh_lc, now).await;
            });

            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "activation_ts": entry.activation_ts,
                    "expires_at":    entry.expires_at,
                    "revoked":       entry.revoked,
                })),
            )
                .into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "No activation record"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

// ── POST /admin/add-key ─────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AddKeyReq {
    token: String,
    key: Option<String>,
    valid_days: Option<i64>,
    note: Option<String>,
}

#[derive(Serialize)]
pub struct AddKeyResp {
    key: String,
    key_hash: String,
    expires_at: i64,
    inserted: bool,
}

pub async fn add_key(
    Extension(pool): Extension<Arc<DbPool>>,
    Extension(_redis): Extension<Arc<RedisPool>>,
    Extension(admin_token): Extension<Arc<String>>,
    Json(req): Json<AddKeyReq>,
) -> impl IntoResponse {
    if !auth::verify_admin_token(&req.token, &admin_token) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "无权限"})),
        )
            .into_response();
    }
    let now = now_secs();
    let expires_at = now + req.valid_days.unwrap_or(365) * 86_400;
    let note = req.note.clone().unwrap_or_default();
    let key = match req.key {
        Some(k) if !k.trim().is_empty() => k.trim().to_string(),
        _ => generate_hkey(),
    };
    let key_hash = hash_key(&key);
    match db::add_key(&pool, &key, &key_hash, expires_at, &note).await {
        Ok(inserted) => (
            StatusCode::CREATED,
            Json(AddKeyResp {
                key,
                key_hash,
                expires_at,
                inserted,
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

// ── GET /admin/licenses ─────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AdminQuery {
    token: String,
}

pub async fn list_licenses(
    Extension(pool): Extension<Arc<DbPool>>,
    Extension(_redis): Extension<Arc<RedisPool>>,
    Extension(admin_token): Extension<Arc<String>>,
    Query(q): Query<AdminQuery>,
) -> impl IntoResponse {
    if !auth::verify_admin_token(&q.token, &admin_token) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "无权限"})),
        )
            .into_response();
    }
    match db::list_all_licenses(&pool).await {
        Ok(r) => (StatusCode::OK, Json(r)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

// ── DELETE /admin/revoke ────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RevokeReq {
    token: String,
    key_hash: String,
    reason: Option<String>,
}

pub async fn revoke_license(
    Extension(pool): Extension<Arc<DbPool>>,
    Extension(redis_pool): Extension<Arc<RedisPool>>, // ✅ 新增
    Extension(admin_token): Extension<Arc<String>>,
    Json(req): Json<RevokeReq>,
) -> impl IntoResponse {
    if !auth::verify_admin_token(&req.token, &admin_token) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "无权限"})),
        )
            .into_response();
    }
    let reason = req.reason.clone().unwrap_or_default();
    match db::revoke_license(&pool, &req.key_hash, &reason).await {
        Ok(_) => {
            // ✅ 吊销后立即失效 Redis 缓存
            let rp = Arc::clone(&redis_pool);
            let kh = req.key_hash.clone();
            tokio::spawn(async move {
                cache::invalidate_verify_cache(&rp, &kh).await;
            });
            (
                StatusCode::OK,
                Json(serde_json::json!({"message": "已吊销"})),
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

// ── POST /admin/extend ──────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ExtendReq {
    token: String,
    key_hash: String,
    extra_days: i64,
}

pub async fn extend_license(
    Extension(pool): Extension<Arc<DbPool>>,
    Extension(redis_pool): Extension<Arc<RedisPool>>, // ✅ 新增
    Extension(admin_token): Extension<Arc<String>>,
    Json(req): Json<ExtendReq>,
) -> impl IntoResponse {
    if !auth::verify_admin_token(&req.token, &admin_token) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "无权限"})),
        )
            .into_response();
    }
    match db::extend_license(&pool, &req.key_hash, req.extra_days * 86_400).await {
        Ok(_) => {
            // ✅ 延期后立即失效 Redis 缓存
            let rp = Arc::clone(&redis_pool);
            let kh = req.key_hash.clone();
            tokio::spawn(async move {
                cache::invalidate_verify_cache(&rp, &kh).await;
            });
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "message": format!("已延长 {} 天", req.extra_days)
                })),
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

// ── GET /health ─────────────────────────────────────────────────────────────

pub async fn health() -> &'static str {
    "ok"
}

// ── POST /admin/batch-init ──────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct BatchInitReq {
    token: String,
    count: Option<u32>,
    note: Option<String>,
}

#[derive(Serialize)]
pub struct BatchInitResp {
    inserted: u64,
    message: String,
}

pub async fn batch_init(
    Extension(pool): Extension<Arc<DbPool>>,
    Extension(_redis): Extension<Arc<RedisPool>>,
    Extension(admin_token): Extension<Arc<String>>,
    Json(req): Json<BatchInitReq>,
) -> impl IntoResponse {
    if !auth::verify_admin_token(&req.token, &admin_token) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "无权限"})),
        )
            .into_response();
    }
    let count = req.count.unwrap_or(200);
    let note = req
        .note
        .clone()
        .unwrap_or_else(|| "系统初始化生成".to_string());
    match db::batch_init_keys(&pool, count, &note).await {
        Ok(inserted) => (
            StatusCode::CREATED,
            Json(BatchInitResp {
                inserted,
                message: format!("成功初始化 {} 个秘钥", inserted),
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}
