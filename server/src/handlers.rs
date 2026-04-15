// server/src/handlers.rs — 请求处理逻辑
use axum::{
    extract::{Json, Extension, Query},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

// ✅ 修复5: 补充 use crate::{auth, db} 导入
// 原代码直接写 db::find_license() 但没有导入，导致 E0433
// ❌ 原写法：没有下面这行，直接用 db::xxx 裸路径
use crate::{auth, db};
use db::{DbPool, LicenseRecord};

// ── 辅助函数：获取当前时间戳（i64）──────────────────
fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

// ─────────────── 激活接口 POST /activate ───────────────
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

    // 防重放：时间戳不得超过 ±60 秒
    if (now - req.timestamp).abs() > 60 {
        return (StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "时间戳偏差过大"})))
            .into_response();
    }

    match db::find_license(&pool, &req.key_hash).await {
        Ok(Some(record)) => {
            // 已激活：幂等返回原始激活时间
            let expires_at = record.expires_at;
            (StatusCode::OK, Json(serde_json::json!({
                "activation_ts": record.activation_ts,
                "expires_at":    expires_at,
                "message":       "已激活（返回原始时间）"
            }))).into_response()
        }
        Ok(None) => {
            // 首次激活：写入数据库
            let record = LicenseRecord {
                key_hash:      req.key_hash.clone(),
                activation_ts: now,
                expires_at:    now + 365 * 24 * 3600,
                revoked:       false,
                created_at:    now,
                note:          String::new(),
            };
            match db::insert_license(&pool, &record).await {
                Ok(_) => (StatusCode::CREATED, Json(serde_json::json!({
                    "activation_ts": now,
                    "expires_at":    now + 365 * 24 * 3600_i64,
                    "message":       "激活成功"
                }))).into_response(),
                Err(e) => {
                    // ✅ 修复6: 提前 let 绑定，消除 E0282 类型推断歧义
                    // ❌ 原写法: Json(serde_json::json!({"error": e.to_string()}))
                    let msg = e.to_string();
                    (StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": msg})))
                        .into_response()
                }
            }
        }
        Err(e) => {
            let msg = e.to_string();
            (StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": msg})))
                .into_response()
        }
    }
}

// ─────────────── 校验接口 POST /verify ───────────────
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
    let _ = &req.signature; // 进阶：可在此做 HMAC 签名验证

    if (now - req.timestamp).abs() > 60 {
        return (StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "时间戳偏差过大"})))
            .into_response();
    }

    match db::find_license(&pool, &req.key_hash).await {
        Ok(Some(record)) => {
            // ✅ 更新最后校验时间，参数改为 i64
            let _ = db::update_last_check(&pool, &req.key_hash, now).await;

            (StatusCode::OK, Json(serde_json::json!({
                "activation_ts": record.activation_ts,
                "expires_at":    record.expires_at,
                "revoked":       record.revoked,
            }))).into_response()
        }
        Ok(None) => {
            (StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "未找到激活记录"})))
                .into_response()
        }
        Err(e) => {
            let msg = e.to_string();
            (StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": msg})))
                .into_response()
        }
    }
}

// ─────────────── 管理接口 ───────────────
#[derive(Deserialize)]
pub struct AdminQuery { token: String }

pub async fn list_licenses(
    Extension(pool): Extension<Arc<DbPool>>,
    Extension(admin_token): Extension<Arc<String>>,
    Query(q): Query<AdminQuery>,
) -> impl IntoResponse {
    if !auth::verify_admin_token(&q.token, &admin_token) {
        return (StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "无权限"})))
            .into_response();
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
    Extension(pool): Extension<Arc<DbPool>>,
    Extension(admin_token): Extension<Arc<String>>,
    Json(req): Json<RevokeReq>,
) -> impl IntoResponse {
    if !auth::verify_admin_token(&req.token, &admin_token) {
        return (StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "无权限"})))
            .into_response();
    }
    match db::revoke_license(&pool, &req.key_hash,
            &req.reason.unwrap_or_default()).await {
        Ok(_) => (StatusCode::OK,
            Json(serde_json::json!({"message": "已吊销"})))
            .into_response(),
        Err(e) => {
            let msg = e.to_string();
            (StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": msg})))
                .into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct ExtendReq {
    token:      String,
    key_hash:   String,
    extra_days: i64,  // ✅ 改为 i64 与 db 函数签名匹配
}

pub async fn extend_license(
    Extension(pool): Extension<Arc<DbPool>>,
    Extension(admin_token): Extension<Arc<String>>,
    Json(req): Json<ExtendReq>,
) -> impl IntoResponse {
    if !auth::verify_admin_token(&req.token, &admin_token) {
        return (StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "无权限"})))
            .into_response();
    }
    let extra_secs = req.extra_days * 86400_i64;
    let days = req.extra_days;
    match db::extend_license(&pool, &req.key_hash, extra_secs).await {
        Ok(_) => (StatusCode::OK,
            Json(serde_json::json!({"message": format!("已延长 {} 天", days)})))
            .into_response(),
        Err(e) => {
            let msg = e.to_string();
            (StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": msg})))
                .into_response()
        }
    }
}

pub async fn health() -> &'static str { "ok" }