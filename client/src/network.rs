// client/src/network.rs — 优化版 v8
// ✅ MINOR-A FIX: SERVER_ID 默认值改为 "license-server-v1"，与服务端对齐
// ✅ MINOR-C FIX: 时钟修正重试补偿网络延迟（记录请求发出时间，计算实际 RTT）
// ✅ 原有: MINOR-3 (MAX_CLOCK_OFFSET_SECS 600s 限制), ERR-TIME-RECORD 解析失败不无限重试

use hmac::{Hmac, Mac};
use obfstr::obfstr;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<sha2::Sha256>;
/// 本地时钟与服务端时钟允许的最大偏差（±600s = ±10分钟）
const MAX_CLOCK_OFFSET_SECS: i64 = 600;
const NET_DEFAULT_TIMEOUT_SECS: u64 = 10;

pub const ERR_REVOKED: &str = "ERR-REVOKED";
pub const ERR_INVALID_KEY: &str = "ERR-INVALID-KEY";
pub const ERR_NOT_ACTIVATED: &str = "ERR-NOT-ACTIVATED";
pub const ERR_EXPIRED: &str = "ERR-EXPIRED";

#[derive(Serialize)]
struct VerifyRequest {
    key_hash: String,
    timestamp: i64,
    signature: String,
}

#[derive(Deserialize)]
pub struct VerifyResponse {
    pub activation_ts: i64,
    pub expires_at: i64,
    pub revoked: bool,
}

static HTTP_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

fn get_http_client() -> &'static reqwest::Client {
    HTTP_CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(NET_DEFAULT_TIMEOUT_SECS))
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

/// 签名格式: HMAC-SHA256(key=hkey, msg=SERVER_ID|key_hash|timestamp)
/// ✅ MINOR-A FIX: 默认值 "license-server-v1" 与服务端 get_server_id() 对齐
fn sign_request(hkey: &str, key_hash: &str, ts: i64, _server_url: &str) -> String {
    let server_id = std::env::var("SERVER_ID").unwrap_or_else(|_| "license-server-v1".to_string()); // ← 与服务端默认值一致
    let mut mac = HmacSha256::new_from_slice(hkey.as_bytes()).unwrap();
    mac.update(server_id.as_bytes());
    mac.update(b"|");
    mac.update(key_hash.as_bytes());
    mac.update(b"|");
    mac.update(ts.to_string().as_bytes());
    format!("{:x}", mac.finalize().into_bytes())
}

fn parse_server_error(status: reqwest::StatusCode, body: &serde_json::Value) -> String {
    let err_code = body["error"].as_str().unwrap_or("unknown");

    match status.as_u16() {
        410 => return ERR_EXPIRED.to_string(),
        403 => match err_code {
            "ERR-REVOKED" | "key revoked" => return ERR_REVOKED.to_string(),
            "ERR-INVALID-KEY" | "invalid key" => return ERR_INVALID_KEY.to_string(),
            "ERR-NOT-ACTIVATED" | "not activated" => return ERR_NOT_ACTIVATED.to_string(),
            _ => return format!("ERR-FORBIDDEN:{}", err_code),
        },
        _ => {}
    }

    match err_code {
        "ERR-REVOKED" => return ERR_REVOKED.to_string(),
        "ERR-INVALID-KEY" => return ERR_INVALID_KEY.to_string(),
        "ERR-NOT-ACTIVATED" => return ERR_NOT_ACTIVATED.to_string(),
        "ERR-EXPIRED" => return ERR_EXPIRED.to_string(),
        _ => {}
    }

    if err_code == "ERR-TIME-RECORD" {
        if let Some(st) = body["server_time"].as_i64() {
            return format!("ERR-TIME-RECORD:server_time={}", st);
        }
    }

    format!("HTTP {} {}", status.as_u16(), err_code)
}

async fn do_verify(
    hkey: &str,
    server_url: &str,
    ts_override: i64, // ✅ 直接传入已修正的时间戳
) -> Result<VerifyResponse, String> {
    let key_hash = hash_key(hkey);
    let signature = sign_request(hkey, &key_hash, ts_override, server_url);
    let req = VerifyRequest {
        key_hash,
        timestamp: ts_override,
        signature,
    };

    let url = format!("{}/verify", server_url);
    let client = get_http_client();
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
        Err(parse_server_error(status, &body))
    }
}

/// 在线验证入口：自动处理时钟偏差（单次重试，补偿网络 RTT）
pub async fn verify_online(hkey: &str, server_url: &str) -> Result<VerifyResponse, String> {
    let local_ts = now_secs();
    let result = do_verify(hkey, server_url, local_ts).await;

    match &result {
        Err(e) if e.starts_with("ERR-TIME-RECORD:server_time=") => {
            let server_time_str = e.trim_start_matches("ERR-TIME-RECORD:server_time=");
            let server_ts = match server_time_str.parse::<i64>() {
                Ok(ts) => ts,

                Err(_) => return Err(e.clone()), // 解析失败，不重试
            };

            // ✅ MINOR-C FIX: 补偿 RTT（假设请求/响应各占一半往返延迟）
            // 用 "当前时间 - 发出请求时时间" 近似 RTT
            let rtt_half = (now_secs() - local_ts).max(0);
            let corrected_ts = server_ts + rtt_half;
            let offset = corrected_ts - now_secs();

            // 超过安全阈值，拒绝同步
            if offset.abs() > MAX_CLOCK_OFFSET_SECS {
                tracing::error!(
                    "[License] Server clock offset {}s exceeds safe threshold {}s, refusing sync",
                    offset,
                    MAX_CLOCK_OFFSET_SECS
                );

                return Err(format!(
                    "server clock offset {}s exceeds safe threshold {}s",
                    offset, MAX_CLOCK_OFFSET_SECS
                ));
            }

            if offset.abs() > 60 {
                tracing::warn!(
                    "[License] Client clock skew {}s detected, consider NTP sync",
                    offset
                );
            }

            // 重试（仅一次）
            do_verify(hkey, server_url, corrected_ts).await
        }
        _ => result,
    }
}
