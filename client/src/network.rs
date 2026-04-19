// client/src/network.rs — 优化版 v7
// ✅ MINOR-3 FIX: ERR-TIME-RECORD 重试，超过 MAX_CLOCK_OFFSET_SECS(600s) 拒绝
// ✅ 说明: 生产环境应使用 HTTPS（rustls-tls），防止 server_time 被 MITM 篡改
// ✅ 改进: server_time 解析失败时返回明确错误，不无限重试

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
/// 与服务端 verify_hmac_signature 完全对应
fn sign_request(hkey: &str, key_hash: &str, ts: i64, server_url: &str) -> String {
    let server_id = std::env::var("SERVER_ID").unwrap_or_else(|_| server_url.to_string());
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

async fn do_verify(hkey: &str, server_url: &str, ts_offset: i64) -> Result<VerifyResponse, String> {
    let ts = now_secs() + ts_offset;
    let key_hash = hash_key(hkey);
    let signature = sign_request(hkey, &key_hash, ts, server_url);
    let req = VerifyRequest {
        key_hash,
        timestamp: ts,
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

/// 在线验证入口：自动处理时钟偏差（单次重试）
pub async fn verify_online(hkey: &str, server_url: &str) -> Result<VerifyResponse, String> {
    let mut ts_offset = 0i64;
    let mut retried = false;
    loop {
        let result = do_verify(hkey, server_url, ts_offset).await;
        if retried {
            return result;
        }
        match &result {
            Err(e) if e.starts_with("ERR-TIME-RECORD:server_time=") => {
                let server_time_str = e.trim_start_matches("ERR-TIME-RECORD:server_time=");
                match server_time_str.parse::<i64>() {
                    Ok(server_ts) => {
                        let offset = server_ts - now_secs();
                        // ✅ MINOR-3 FIX: 超过 MAX_CLOCK_OFFSET_SECS 拒绝同步
                        if offset.abs() > MAX_CLOCK_OFFSET_SECS {
                            tracing::error!(
                                "[License] 服务端时钟偏差 {}s 超过安全阈值 {}s，拒绝同步",
                                offset,
                                MAX_CLOCK_OFFSET_SECS
                            );
                            return Err(format!(
                                "server clock offset {}s exceeds safe threshold {}s",
                                offset, MAX_CLOCK_OFFSET_SECS
                            ));
                        }
                        if offset.abs() > 60 {
                            tracing::warn!("[License] 客户端时钟偏差 {}s，建议同步 NTP", offset);
                        }
                        ts_offset = offset;
                        retried = true; // 继续 loop，使用 ts_offset 重试
                    }
                    Err(_) => {
                        // ✅ 解析失败，返回原始错误，不无限重试
                        return Err(e.clone());
                    }
                }
            }
            _ => return result,
        }
    }
}
