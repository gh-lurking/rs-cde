// client/src/network.rs — 优化版 v9
//
// ✅ BUG-4 FIX: RTT 补偿修正
//   原始代码: rtt_half = now_secs() - local_ts  ← 实际是完整 RTT！
//   修复后:  full_rtt = t4 - local_ts; rtt_half = full_rtt / 2  ← 真正的单程延迟
// ✅ 保留原有: MINOR-A（SERVER_ID 默认值与服务端对齐），MINOR-3（MAX_CLOCK_OFFSET 600s）

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
/// ✅ MINOR-A: 默认值 "license-server-v1" 与服务端 get_server_id() 对齐
fn sign_request(hkey: &str, key_hash: &str, ts: i64, _server_url: &str) -> String {
    let server_id = std::env::var("SERVER_ID").unwrap_or_else(|_| "license-server-v1".to_string());
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
        // ✅ BUG-3 FIX 对应：服务端现在返回 409 Conflict 表示未激活
        409 if err_code == "ERR-NOT-ACTIVATED" => return ERR_NOT_ACTIVATED.to_string(),
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
    ts_override: i64,
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

/// 在线验证入口：自动处理时钟偏差（单次重试）
///
/// ✅ BUG-4 FIX: RTT 补偿修正
/// NTP 单向延迟估算（对称假设）：
///   T1 = local_ts（发出请求前）
///   T4 = t4（收到响应后）
///   full_RTT = T4 - T1
///   rtt_half = full_RTT / 2（单向延迟估算）
///   corrected_ts = server_ts + rtt_half（响应在途期间服务端时钟走过的时间）
pub async fn verify_online(hkey: &str, server_url: &str) -> Result<VerifyResponse, String> {
    let local_ts = now_secs(); // T1
    let result = do_verify(hkey, server_url, local_ts).await;

    match &result {
        Err(e) if e.starts_with("ERR-TIME-RECORD:server_time=") => {
            let server_time_str = e.trim_start_matches("ERR-TIME-RECORD:server_time=");
            let server_ts = match server_time_str.parse::<i64>() {
                Ok(ts) => ts,
                Err(_) => return Err(e.clone()), // 解析失败，不重试
            };

            // ✅ BUG-4 FIX: 正确的 RTT/2 计算
            let t4 = now_secs(); // T4: 收到响应后的时间
            let full_rtt = (t4 - local_ts).max(0); // 完整往返时延
            let rtt_half = full_rtt / 2; // 单向延迟估算（对称假设）

            // corrected_ts ≈ 服务端当前时间（响应发出后 rtt_half 已过去）
            let corrected_ts = server_ts + rtt_half;

            let offset = corrected_ts - t4; // 时钟偏差

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
