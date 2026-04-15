// server/src/handlers.rs — 请求处理逻辑
//
// ✅ 变更1: activate() — 首次激活前检查 key_hash 是否存在于 DB（由管理员预置）
//            若不存在则拒绝激活，彻底消除客户端硬编码 VALID_KEYS 的需要
// ✅ 变更2: verify() — 返回 expires_at，客户端据此判断是否过期并直接退出
// ✅ 变更3: 新增 add_key() handler，对应 POST /admin/add-key 接口
//            管理员通过此接口批量预置 License Key（明文 + hash + 有效期）

use axum::{
    extract::{Json, Extension, Query},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::{auth, db};
use db::{DbPool, LicenseRecord};

// ── 辅助函数 ──────────────────────────────────────────────────────────────────

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// SHA256(key) → hex string
fn hash_key(key: &str) -> String {
    let mut h = Sha256::new();
    h.update(key.as_bytes());
    format!("{:x}", h.finalize())
}

/// 生成格式为 HKEY-XXXX-XXXX-XXXX 的随机秘钥（基于 UUID v4）
fn generate_hkey() -> String {
    // UUID v4 = 32 hex chars，拆为 3×8 字符段
    let uid = Uuid::new_v4().to_simple().to_string().to_uppercase();
    // 取前 20 字符，分为 3 段
    format!("HKEY-{}-{}-{}", &uid[0..4], &uid[4..8], &uid[8..12])
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /activate — 客户端首次激活
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ActivateReq {
    key_hash:  String,
    timestamp: i64,
    signature: String,
}

pub async fn activate(
    Extension(pool): Extension<Arc<DbPool>>,
    Json(req): Json<ActivateReq>,
) -> impl IntoResponse {
    let now = now_secs();

    // 防重放：时间戳偏差不超过 ±60 秒
    if (now - req.timestamp).abs() > 60 {
        return (StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "时间戳偏差过大"}))).into_response();
    }

    let _ = &req.signature; // 进阶可做 HMAC 验签

    match db::find_license(&pool, &req.key_hash).await {
        Ok(Some(record)) => {
            if record.activation_ts == 0 {
                // ✅ 变更1a: key 存在但尚未激活 → 写入激活时间（首次激活）
                let activated_at = now;
                let expires_at   = record.expires_at; // 使用管理员预设的过期时间

                let updated = LicenseRecord {
                    activation_ts: activated_at,
                    ..record
                };
                // 用 upsert 更新激活时间
                let _ = sqlx::query(
                    "UPDATE licenses SET activation_ts = $1 WHERE key_hash = $2"
                )
                .bind(activated_at)
                .bind(&req.key_hash)
                .execute(pool.as_ref())
                .await;

                (StatusCode::CREATED, Json(serde_json::json!({
                    "activation_ts": activated_at,
                    "expires_at":    expires_at,
                    "message":       "激活成功"
                }))).into_response()
            } else {
                // 已激活：幂等返回原始激活时间
                (StatusCode::OK, Json(serde_json::json!({
                    "activation_ts": record.activation_ts,
                    "expires_at":    record.expires_at,
                    "message":       "已激活（返回原始时间）"
                }))).into_response()
            }
        }
        Ok(None) => {
            // ✅ 变更1b: key_hash 不在 DB 中 → 拒绝激活
            // 原逻辑（SQLite 版）在此处直接 INSERT，默认所有 key 都有效。
            // 新逻辑要求 key 必须由管理员通过 /admin/add-key 预置后才可激活，
            // 彻底消除客户端 VALID_KEYS 硬编码白名单的必要。
            (StatusCode::FORBIDDEN, Json(serde_json::json!({
                "error": "无效或未授权的秘钥，请联系管理员"
            }))).into_response()
        }
        Err(e) => {
            let msg = e.to_string();
            (StatusCode::INTERNAL_SERVER_ERROR,
             Json(serde_json::json!({"error": msg}))).into_response()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /verify — 客户端周期性在线校验
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct VerifyReq {
    key_hash:  String,
    timestamp: i64,
    signature: String,
}

pub async fn verify(
    Extension(pool): Extension<Arc<DbPool>>,
    Json(req): Json<VerifyReq>,
) -> impl IntoResponse {
    let now = now_secs();
    let _ = &req.signature;

    if (now - req.timestamp).abs() > 60 {
        return (StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "时间戳偏差过大"}))).into_response();
    }

    match db::find_license(&pool, &req.key_hash).await {
        Ok(Some(record)) => {
            let _ = db::update_last_check(&pool, &req.key_hash, now).await;

            // ✅ 变更2: 返回 expires_at，客户端收到后与当前时间比较，
            //   若 now >= expires_at 则客户端主动退出，无需服务端多一次判断。
            //   revoked=true 时客户端同样退出。
            (StatusCode::OK, Json(serde_json::json!({
                "activation_ts": record.activation_ts,
                "expires_at":    record.expires_at,
                "revoked":       record.revoked,
            }))).into_response()
        }
        Ok(None) => {
            (StatusCode::NOT_FOUND,
             Json(serde_json::json!({"error": "未找到激活记录"}))).into_response()
        }
        Err(e) => {
            let msg = e.to_string();
            (StatusCode::INTERNAL_SERVER_ERROR,
             Json(serde_json::json!({"error": msg}))).into_response()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ✅ 变更3: POST /admin/add-key — 管理员批量预置 License Key
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AddKeyReq {
    /// 管理员 Token（鉴权）
    token: String,
    /// 指定明文 key（可选）；不填则服务端自动生成 HKEY-XXXX-XXXX-XXXX
    key: Option<String>,
    /// 有效天数（默认 365 天）
    valid_days: Option<i64>,
    /// 管理员备注（可选）
    note: Option<String>,
}

#[derive(Serialize)]
pub struct AddKeyResp {
    /// 生成或接收到的明文 key（分发给最终用户）
    key:        String,
    /// SHA256(key) hex（入库索引）
    key_hash:   String,
    /// 过期 Unix 时间戳
    expires_at: i64,
    /// 是否为本次新增（false 表示 key_hash 已存在）
    inserted:   bool,
}

pub async fn add_key(
    Extension(pool):        Extension<Arc<DbPool>>,
    Extension(admin_token): Extension<Arc<String>>,
    Json(req):              Json<AddKeyReq>,
) -> impl IntoResponse {
    // 鉴权
    if !auth::verify_admin_token(&req.token, &admin_token) {
        return (StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "无权限"}))).into_response();
    }

    let now        = now_secs();
    let valid_days = req.valid_days.unwrap_or(365);
    let expires_at = now + valid_days * 86_400;
    let note       = req.note.clone().unwrap_or_default();

    // 明文 key：调用方提供 or 服务端生成
    let key = match req.key {
        Some(k) if !k.trim().is_empty() => k.trim().to_string(),
        _ => generate_hkey(),
    };
    let key_hash = hash_key(&key);

    match db::add_key(&pool, &key, &key_hash, expires_at, &note).await {
        Ok(inserted) => {
            (StatusCode::CREATED, Json(AddKeyResp {
                key,
                key_hash,
                expires_at,
                inserted,
            })).into_response()
        }
        Err(e) => {
            let msg = e.to_string();
            (StatusCode::INTERNAL_SERVER_ERROR,
             Json(serde_json::json!({"error": msg}))).into_response()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 管理接口（原有，无核心逻辑变更）
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AdminQuery { token: String }

pub async fn list_licenses(
    Extension(pool):        Extension<Arc<DbPool>>,
    Extension(admin_token): Extension<Arc<String>>,
    Query(q):               Query<AdminQuery>,
) -> impl IntoResponse {
    if !auth::verify_admin_token(&q.token, &admin_token) {
        return (StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "无权限"}))).into_response();
    }
    match db::list_all_licenses(&pool).await {
        Ok(records) => (StatusCode::OK, Json(records)).into_response(),
        Err(e) => {
            let msg = e.to_string();
            (StatusCode::INTERNAL_SERVER_ERROR,
             Json(serde_json::json!({"error": msg}))).into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct RevokeReq {
    token:    String,
    key_hash: String,
    reason:   Option<String>,
}

pub async fn revoke_license(
    Extension(pool):        Extension<Arc<DbPool>>,
    Extension(admin_token): Extension<Arc<String>>,
    Json(req):              Json<RevokeReq>,
) -> impl IntoResponse {
    if !auth::verify_admin_token(&req.token, &admin_token) {
        return (StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "无权限"}))).into_response();
    }
    match db::revoke_license(&pool, &req.key_hash,
                             &req.reason.clone().unwrap_or_default()).await {
        Ok(_) => (StatusCode::OK,
                  Json(serde_json::json!({"message": "已吊销"}))).into_response(),
        Err(e) => {
            let msg = e.to_string();
            (StatusCode::INTERNAL_SERVER_ERROR,
             Json(serde_json::json!({"error": msg}))).into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct ExtendReq {
    token:      String,
    key_hash:   String,
    extra_days: i64,
}

pub async fn extend_license(
    Extension(pool):        Extension<Arc<DbPool>>,
    Extension(admin_token): Extension<Arc<String>>,
    Json(req):              Json<ExtendReq>,
) -> impl IntoResponse {
    if !auth::verify_admin_token(&req.token, &admin_token) {
        return (StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "无权限"}))).into_response();
    }
    let extra_secs = req.extra_days * 86_400_i64;
    let days       = req.extra_days;
    match db::extend_license(&pool, &req.key_hash, extra_secs).await {
        Ok(_) => (StatusCode::OK, Json(serde_json::json!({
            "message": format!("已延长 {} 天", days)
        }))).into_response(),
        Err(e) => {
            let msg = e.to_string();
            (StatusCode::INTERNAL_SERVER_ERROR,
             Json(serde_json::json!({"error": msg}))).into_response()
        }
    }
}

pub async fn health() -> &'static str { "ok" }
