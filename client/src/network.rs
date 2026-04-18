// client/src/network.rs — 优化版
// BUG-G FIX: 收到 ERR-TIME-RECORD 时，提取服务端时间自动重试一次
// BUG-J FIX: 全局单例 Client，连接池跨调用复用（OnceLock 线程安全）

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

#[derive(Serialize)]
struct VerifyRequest {
    key_hash: String,
    timestamp: i64,
    signature: String,
}

// BUG-05 FIX: 统一使用 i64，避免 u64→i64 转换溢出
#[derive(Deserialize)]
pub struct VerifyResponse {
    pub activation_ts: i64,
    pub expires_at: i64,
    pub revoked: bool,
}

// BUG-J FIX: 全局单例 Client，连接池跨调用复用
static HTTP_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

fn get_http_client(timeout_secs: u64) -> &'static reqwest::Client {
    HTTP_CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(timeout_secs))
            .tcp_keepalive(std::time::Duration::from_secs(60))
            .pool_max_idle_per_host(4)
            .build()
            .expect("Failed to build HTTP client")
    })
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

pub fn hash_key(hkey: &str) -> String {
    let mut h = Sha256::new();
    h.update(hkey.as_bytes());
    format!("{:x}", h.finalize())
}

fn sign_request(hkey: &str, key_hash: &str, ts: i64) -> String {
    let mut mac = HmacSha256::new_from_slice(hkey.as_bytes()).unwrap();
    mac.update(key_hash.as_bytes());
    mac.update(b"|");
    mac.update(ts.to_string().as_bytes());
    format!("{:x}", mac.finalize().into_bytes())
}

/// BUG-G FIX: 支持时间偏移的单次请求（ts_offset 用于时钟修正重试）
async fn do_verify(
    hkey: &str,
    server_url: &str,
    timeout_secs: u64,
    ts_offset: i64, // 时钟偏差补偿值（正常调用传 0）
) -> Result<VerifyResponse, String> {
    let ts = now_secs() + ts_offset;
    let key_hash = hash_key(hkey);
    let signature = sign_request(hkey, &key_hash, ts);

    let req = VerifyRequest {
        key_hash,
        timestamp: ts,
        signature,
    };
    let url = format!("{}/verify", server_url);

    // BUG-J FIX: 复用全局 Client（避免每次重建 TCP/TLS 连接）
    let client = get_http_client(timeout_secs);
    let resp = client
        .post(&url)
        .json(&req)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let status = resp.status();
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("JSON decode error: {e}"))?;

    if status.is_success() {
        serde_json::from_value(body).map_err(|e| e.to_string())
    } else {
        let err_msg = body["error"]
            .as_str()
            .unwrap_or("unknown error")
            .to_string();
        // BUG-G FIX: 将 server_time 附加到错误信息中，供调用方重试
        if let Some(st) = body["server_time"].as_i64() {
            Err(format!("ERR-TIME-RECORD:server_time={}", st))
        } else {
            Err(err_msg)
        }
    }
}

/// 主入口：在线校验，收到时钟错误时自动修正重试一次
/// BUG-G FIX: 自动时钟修正
/// BUG-J FIX: 全局 Client 单例
pub async fn verify_online(
    hkey: &str,
    server_url: &str,
    timeout_secs: u64,
) -> Result<VerifyResponse, String> {
    let result = do_verify(hkey, server_url, timeout_secs, 0).await;

    match &result {
        Err(e) if e.starts_with("ERR-TIME-RECORD:server_time=") => {
            // 提取服务端时间，计算偏移后重试一次
            let server_time_str = e.trim_start_matches("ERR-TIME-RECORD:server_time=");
            if let Ok(server_ts) = server_time_str.parse::<i64>() {
                let offset = server_ts - now_secs();
                tracing::warn!("[License] 时钟偏差 {}s，自动修正后重试", offset);
                return do_verify(hkey, server_url, timeout_secs, offset).await;
            }
            result
        }
        _ => result,
    }
}
