// client/src/network.rs — 优化版 v4
// [FIX-1] 新增 ERR_EXPIRED 常量 + parse_server_error 处理
//   原Bug: 服务端返回 ERR-EXPIRED (402) 时，客户端不识别此错误码，
//   将其当作网络错误降级到离线缓存，若客户端时钟落后则可能绕过过期校验。
// M-04 FIX: 用 loop + retried flag 替代 async_recursion
// CRIT-3 FIX: 明确区分业务拒绝错误码与网络错误
// MAJOR-3 FIX: 时钟重试严格限制为一次

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<sha2::Sha256>;
/// 时钟偏差安全阈值（±600s = ±10分钟）
const MAX_CLOCK_OFFSET_SECS: i64 = 600;
const NET_DEFAULT_TIMEOUT_SECS: u64 = 10;

/// 业务拒绝错误前缀
pub const ERR_REVOKED: &str = "ERR-REVOKED";
pub const ERR_INVALID_KEY: &str = "ERR-INVALID-KEY";
pub const ERR_NOT_ACTIVATED: &str = "ERR-NOT-ACTIVATED";
pub const ERR_EXPIRED: &str = "ERR-EXPIRED"; // [FIX-1] 新增过期错误码

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

fn sign_request(hkey: &str, key_hash: &str, ts: i64) -> String {
    let mut mac = HmacSha256::new_from_slice(hkey.as_bytes()).unwrap();
    mac.update(key_hash.as_bytes());
    mac.update(b"|");
    mac.update(ts.to_string().as_bytes());
    format!("{:x}", mac.finalize().into_bytes())
}

/// 解析非 2xx 响应，明确区分业务错误与网络错误
fn parse_server_error(status: reqwest::StatusCode, body: &serde_json::Value) -> String {
    let err_code = body["error"].as_str().unwrap_or("unknown");
    match err_code {
        "ERR-REVOKED" | "key revoked" => return ERR_REVOKED.to_string(),
        "ERR-INVALID-KEY" | "invalid key" => return ERR_INVALID_KEY.to_string(),
        "ERR-NOT-ACTIVATED" | "not activated" => return ERR_NOT_ACTIVATED.to_string(),
        "ERR-EXPIRED" | "expired" => return ERR_EXPIRED.to_string(), // [FIX-1] 新增
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
    let signature = sign_request(hkey, &key_hash, ts);

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

/// 用 loop + retried flag 替代 async_recursion
/// 时钟重试严格限制一次，防无限重试
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
                if let Ok(server_ts) = server_time_str.parse::<i64>() {
                    let offset = server_ts - now_secs();
                    if offset.abs() > MAX_CLOCK_OFFSET_SECS {
                        tracing::error!(
                            "[License] 服务端时钟偏差 {}s 超过安全阈值 {}s，拒绝修正",
                            offset,
                            MAX_CLOCK_OFFSET_SECS
                        );
                        return Err(format!(
                            "server clock offset {}s exceeds safe threshold {}s",
                            offset, MAX_CLOCK_OFFSET_SECS
                        ));
                    }
                    tracing::warn!("[License] 时钟偏差 {}s，自动修正后重试（仅此一次）", offset);
                    ts_offset = offset;
                    retried = true;
                    continue;
                }
                return result;
            }
            _ => return result,
        }
    }
}
