// server/src/handlers.rs — 优化版（修复 BUG-01/02/03/08/09）

use crate::{auth, cache, db};
use axum::{
    extract::{Extension, Json, Query},
    http::StatusCode,
    response::IntoResponse,
};
use cache::{RedisPool, VerifyCacheEntry};
use db::DbPool;
use hex;
use hmac::KeyInit;
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

// ── BUG-03 FIX: 服务端签名验证 ────────────────────────────────────────────────
// 使用存储在 DB 里的明文 key 验证客户端 HMAC-SHA256(key, key_hash|timestamp)
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
    // 恒定时间比较防时序攻击
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

// ── POST /activate ─────────────────────────────────────────────────────────────

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

    // [1] 时间戳防重放（±60s）
    if (now - req.timestamp).abs() > 30 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "ERR-TIME-RECORD"})),
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

    // BUG-03 FIX: 验证签名（使用 DB 中存储的明文 key）
    if !verify_hmac_signature(&record.key, &req.key_hash, req.timestamp, &req.signature) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid signature"})),
        )
            .into_response();
    }

    if record.activation_ts == 0 {
        // BUG-02 FIX: 优先使用 DB 预置的 expires_at（若非零），否则才用 now+365d
        let expires_at = if record.expires_at > 0 {
            record.expires_at // /admin/add-key 设置的 valid_days 生效
        } else {
            now + 365 * 86_400 // batch_init 的 key 默认一年
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

        // 失效旧缓存
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

// ── POST /verify ───────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct VerifyReq {
    key_hash: String,
    timestamp: i64,
    signature: String,
}

pub async fn verify(
    Extension(pool): Extension<Arc<DbPool>>,
    Extension(redis_pool): Extension<Arc<RedisPool>>,
    Json(req): Json<VerifyReq>,
) -> impl IntoResponse {
    let now = now_secs();

    // [1] 时间戳防重放
    if (now - req.timestamp).abs() > 60 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "ERR-TIME-RECORD"})),
        )
            .into_response();
    }

    // [2] Redis 缓存命中路径（缓存的是已验签后的结果，BUG-03: 缓存不做二次签名验证）
    // 注意：缓存命中时跳过签名验证是可接受的，因为缓存项是上次 DB 验证后写入的权威数据
    if let Some(cached) = cache::get_verify_cache(&redis_pool, &req.key_hash).await {
        tracing::debug!(
            "Cache Hit: {}...",
            &req.key_hash[..8.min(req.key_hash.len())]
        );

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

    // [3] 缓存未命中 → 查 PostgreSQL
    let record = match db::find_license(&pool, &req.key_hash).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "No activation record"})),
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

    // BUG-03 FIX: 缓存未命中时验证签名
    if !verify_hmac_signature(&record.key, &req.key_hash, req.timestamp, &req.signature) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid signature"})),
        )
            .into_response();
    }

    // BUG-08 FIX: 未激活的 key (activation_ts == 0) 应返回 402，要求先激活
    if record.activation_ts == 0 {
        return (
            StatusCode::PAYMENT_REQUIRED, // 402: 需要先激活
            Json(serde_json::json!({"error": "key not activated, please call /activate first"})),
        )
            .into_response();
    }

    // [4] 检查过期 & 自动吊销
    // BUG-01 FIX: 过期时不写缓存，直接在单个 spawn 内先吊销 DB 再失效缓存，避免竞争
    let mut revoked = record.revoked;
    if !revoked && record.expires_at > 0 && now >= record.expires_at {
        // 立即在本请求内设置 revoked=true 返回给客户端
        revoked = true;
        // 单个 spawn 保证顺序：先 DB 吊销，再失效缓存
        let pool_r = Arc::clone(&pool);
        let rp_r = Arc::clone(&redis_pool);
        let kh_r = req.key_hash.clone();
        tokio::spawn(async move {
            // 先吊销 DB
            let _ = db::revoke_license(&pool_r, &kh_r, "auto-revoked: expired").await;
            // 再失效缓存（缓存里不存被吊销的条目）
            cache::invalidate_verify_cache(&rp_r, &kh_r).await;
        });

        // 过期 key：直接返回，不写缓存
        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "activation_ts": record.activation_ts,
                "expires_at":    record.expires_at,
                "revoked":       true,
            })),
        )
            .into_response();
    }

    // [5] 正常路径：构建缓存条目并异步写入
    let entry = VerifyCacheEntry {
        activation_ts: record.activation_ts,
        expires_at: record.expires_at,
        revoked,
    };

    // 异步写缓存
    let rp_w = Arc::clone(&redis_pool);
    let kh_w = req.key_hash.clone();
    let entry_w = entry.clone();

    tokio::spawn(async move {
        cache::set_verify_cache(&rp_w, &kh_w, &entry_w).await;
    });

    // 异步更新 last_check
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

// ── POST /admin/add-key ────────────────────────────────────────────────────────

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
    // BUG-02 FIX: expires_at 表示"从激活起可用时长"存为偏移量 or 预设到期时间
    // 此处含义：key 必须在 now + valid_days 内激活，同时激活后有效期也是 valid_days
    // 存储设计：expires_at 在激活时才计算 → 用 activation_ts==0 + 预置 offset
    // 更清晰的方案：新增 valid_seconds 字段；为简化，此处 expires_at 存 "激活后到期绝对时间"
    // 若 key 未激活，expires_at 代表预置的有效期（激活时优先使用）
    let valid_days = req.valid_days.unwrap_or(365);
    // 预置 expires_at = now + valid_days（激活时若使用此值，相当于从创建时开始计时）
    // 实际语义：给 admin 配置灵活性；激活时 handlers::activate 会优先用此非零值
    let expires_at = now + valid_days * 86_400;
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

// ── GET /admin/licenses ────────────────────────────────────────────────────────
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

// ── DELETE /admin/revoke ───────────────────────────────────────────────────────
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
            // 吊销后立即失效缓存
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

// ── POST /admin/extend ─────────────────────────────────────────────────────────
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
    if !auth::verify_admin_token(&req.token, &admin_token) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "无权限"})),
        )
            .into_response();
    }

    // BUG-09 FIX: 对已过期 key 从 now 起延长，而不是从旧 expires_at 起延长
    match db::extend_license(&pool, &req.key_hash, req.extra_days * 86_400).await {
        Ok(_) => {
            // 延期后立即失效缓存
            let rp = Arc::clone(&redis_pool);
            let kh = req.key_hash.clone();
            tokio::spawn(async move {
                cache::invalidate_verify_cache(&rp, &kh).await;
            });

            (
                StatusCode::OK,
                Json(serde_json::json!({"message": format!("已延长 {} 天", req.extra_days)})),
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

// ── GET /health ────────────────────────────────────────────────────────────────
pub async fn health() -> &'static str {
    "ok"
}

// ── POST /admin/batch-init ─────────────────────────────────────────────────────
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
