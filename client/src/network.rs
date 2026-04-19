// client/src/network.rs — 优化版 v10
//
// ✅ BUG-4 FIX: RTT 半程估算修正（full_rtt = T4-T1; rtt_half = full_rtt/2）
// ✅ MINOR-A FIX: server_id 从 /health 接口获取，而非本地 env var
// ✅ MINOR-3 FIX: MAX_CLOCK_OFFSET 600s；BUG-3 FIX: 409 冲突码解析

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

/// ✅ MINOR-A FIX: 从 /health 接口缓存 server_id
static SERVER_ID_CACHE: OnceLock<String> = OnceLock::new();

async fn fetch_server_id(server_url: &str) -> String {
    #[derive(Deserialize)]
    struct HealthResp {
        server_id: String,
    }
    let client = get_http_client();
    let url = format!("{}/health", server_url);
    match client.get(&url).send().await {
        Ok(resp) => {
            if let Ok(h) = resp.json::<HealthResp>().await {
                return h.server_id;
            }
        }
        Err(e) => {
            tracing::warn!("[Network] Failed to fetch server_id from /health: {}", e);
        }
    }
    // fallback: 环境变量或默认值
    std::env::var("SERVER_ID").unwrap_or_else(|_| "license-server-v1".to_string())
}

async fn get_server_id(server_url: &str) -> &'static str {
    if let Some(id) = SERVER_ID_CACHE.get() {
        return id;
    }
    let id = fetch_server_id(server_url).await;
    SERVER_ID_CACHE.get_or_init(|| id)
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

/// HMAC-SHA256(key=hkey, msg=server_id|key_hash|timestamp)
/// ✅ MINOR-A FIX: server_id 从 /health 接口获取
async fn sign_request(hkey: &str, key_hash: &str, ts: i64, server_url: &str) -> String {
    let server_id = get_server_id(server_url).await;
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
        // ✅ BUG-3 FIX: 409 Conflict 映射到 ERR-NOT-ACTIVATED
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
    let signature = sign_request(hkey, &key_hash, ts_override, server_url).await;
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

/// ✅ BUG-4 FIX: 正确的 RTT 半程估算（NTP-style）
///
/// T1 = local_ts（发送前）
/// T4 = t4（收到响应后）
/// full_RTT = T4 - T1
/// rtt_half = full_RTT / 2（正确的单程估算）
/// corrected_ts = server_ts + rtt_half
pub async fn verify_online(hkey: &str, server_url: &str) -> Result<VerifyResponse, String> {
    let t1 = now_secs(); // T1
    let result = do_verify(hkey, server_url, t1).await;

    match &result {
        Err(e) if e.starts_with("ERR-TIME-RECORD:server_time=") => {
            let server_time_str = e.trim_start_matches("ERR-TIME-RECORD:server_time=");
            let server_ts = match server_time_str.parse::<i64>() {
                Ok(ts) => ts,
                Err(_) => return result,
            };

            let t4 = now_secs(); // T4：收到响应后
            let full_rtt = t4 - t1; // ✅ BUG-4 FIX: 完整 RTT = T4 - T1

            // 合理性检查：RTT 不应超过超时时间
            if full_rtt < 0 || full_rtt > NET_DEFAULT_TIMEOUT_SECS as i64 * 2 {
                eprintln!(
                    "[Network] Unreasonable RTT: {}s, skipping time correction",
                    full_rtt
                );
                return result;
            }

            let rtt_half = full_rtt / 2; // ✅ 正确半程 RTT
            let corrected_ts = server_ts + rtt_half; // ✅ NTP-style 校正

            // 验证时钟偏差是否在允许范围内
            let clock_offset = (t1 - corrected_ts).abs();
            if clock_offset > MAX_CLOCK_OFFSET_SECS {
                eprintln!(
                    "[Network] Clock offset {}s exceeds limit {}s, aborting",
                    clock_offset, MAX_CLOCK_OFFSET_SECS
                );
                return Err(format!("ERR-CLOCK-SKEW:{}", clock_offset));
            }

            eprintln!(
                "[Network] Time corrected: local={} server={} rtt_half={}s corrected={}",
                t1, server_ts, rtt_half, corrected_ts
            );
            // 用校正后的时间戳重试
            do_verify(hkey, server_url, corrected_ts).await
        }
        _ => result,
    }
}
