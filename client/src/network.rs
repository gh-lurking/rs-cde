// client/src/network.rs — 增强时间校验版
// 关键修复：validate_system_time 使用真实 HTTPS 时间校验

use hmac::{Hmac, Mac};
// use obfstr::obfstr;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;
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
        Err(e) => tracing::warn!("[Network] Failed to fetch server_id: {}", e),
    }
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
        409 if err_code == "ERR-NOT-ACTIVATED" => return ERR_NOT_ACTIVATED.to_string(),
        _ => {}
    }

    match err_code {
        "ERR-REVOKED" => ERR_REVOKED.to_string(),
        "ERR-INVALID-KEY" => ERR_INVALID_KEY.to_string(),
        "ERR-NOT-ACTIVATED" => ERR_NOT_ACTIVATED.to_string(),
        "ERR-EXPIRED" => ERR_EXPIRED.to_string(),
        "ERR-TIME-RECORD" => {
            if let Some(st) = body["server_time"].as_i64() {
                format!("ERR-TIME-RECORD:server_time={}", st)
            } else {
                format!("HTTP {} {}", status.as_u16(), err_code)
            }
        }
        _ => format!("HTTP {} {}", status.as_u16(), err_code),
    }
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

pub async fn verify_online(hkey: &str, server_url: &str) -> Result<VerifyResponse, String> {
    let t1 = now_secs();
    let result = do_verify(hkey, server_url, t1).await;

    match &result {
        Err(e) if e.starts_with("ERR-TIME-RECORD:server_time=") => {
            let server_time_str = e.trim_start_matches("ERR-TIME-RECORD:server_time=");
            let server_ts = match server_time_str.parse::<i64>() {
                Ok(ts) => ts,
                Err(_) => return result,
            };

            let t4 = now_secs();
            let full_rtt = t4 - t1;
            if full_rtt > NET_DEFAULT_TIMEOUT_SECS as i64 * 2 {
                eprintln!("[Network] Unreasonable RTT: {}s", full_rtt);
                return result;
            }

            let rtt_half = full_rtt / 2;
            let corrected_ts = server_ts + rtt_half;
            let clock_offset = (t1 - corrected_ts).abs();

            if clock_offset > MAX_CLOCK_OFFSET_SECS {
                eprintln!("[Network] Clock offset {}s exceeds limit", clock_offset);
                return Err(format!("ERR-CLOCK-SKEW:{}", clock_offset));
            }

            eprintln!(
                "[Network] Time corrected: local={} server={}",
                t1, server_ts
            );

            let retry = do_verify(hkey, server_url, corrected_ts).await;
            match &retry {
                Err(e2) if e2.starts_with("ERR-TIME-RECORD:") => {
                    Err(format!("ERR-CLOCK-SKEW-PERSISTENT:server={}", server_ts))
                }
                _ => retry,
            }
        }
        _ => result,
    }
}

/// 增强的系统时间校验
pub async fn validate_system_time() -> Result<(), String> {
    let local_now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // 基本范围检查
    let min_ts: u64 = 1704067200; // 2024-01-01
    let max_ts: u64 = 1893456000; // 2030-01-01

    if local_now < min_ts || local_now > max_ts {
        return Err(format!("System time outside reasonable range"));
    }

    // 通过 HTTPS 响应头验证时间
    let client = get_http_client();
    let time_sources = [
        "https://www.google.com",
        "https://www.cloudflare.com",
        "https://www.microsoft.com",
    ];

    let mut valid_checks = 0;
    let mut total_offset: i64 = 0;

    for url in time_sources {
        if let Ok(resp) = client
            .head(url)
            .timeout(Duration::from_secs(5))
            .send()
            .await
        {
            if let Some(date) = resp.headers().get("date") {
                if let Ok(date_str) = date.to_str() {
                    // 解析 HTTP Date header (RFC 7231 格式)
                    if let Some(server_time) = parse_http_date_to_timestamp(date_str) {
                        let offset = local_now as i64 - server_time as i64;
                        total_offset += offset;
                        valid_checks += 1;
                        tracing::info!("[Time] Source: {}, offset: {}s", url, offset);
                    }
                }
            }
        }
    }

    if valid_checks == 0 {
        tracing::warn!("[Time] No time sources available, using basic validation only");
        return Ok(());
    }

    let avg_offset = total_offset / valid_checks as i64;
    if avg_offset.abs() > 3600 {
        return Err(format!(
            "System time deviation too large: {}s (avg from {} sources)",
            avg_offset, valid_checks
        ));
    }

    if avg_offset.abs() > 300 {
        tracing::warn!("[Time] System time has significant offset: {}s", avg_offset);
    }

    Ok(())
}

/// 解析 HTTP Date header 为 Unix 时间戳
/// 支持格式: "Mon, 01 Jan 2024 00:00:00 GMT"
fn parse_http_date_to_timestamp(date_str: &str) -> Option<u64> {
    let months = [
        ("Jan", 1),
        ("Feb", 2),
        ("Mar", 3),
        ("Apr", 4),
        ("May", 5),
        ("Jun", 6),
        ("Jul", 7),
        ("Aug", 8),
        ("Sep", 9),
        ("Oct", 10),
        ("Nov", 11),
        ("Dec", 12),
    ];

    let parts: Vec<&str> = date_str.split_whitespace().collect();
    if parts.len() < 5 {
        return None;
    }

    // 格式: Mon, 01 Jan 2024 00:00:00 GMT
    // 或:   01 Jan 2024 00:00:00 GMT (无前缀)
    let date_part_idx = if parts[0].ends_with(',') { 1 } else { 0 };

    if parts.len() < date_part_idx + 4 {
        return None;
    }

    let day: u32 = parts[date_part_idx].parse().ok()?;
    let month_name = parts[date_part_idx + 1];
    let year: i32 = parts[date_part_idx + 2].parse().ok()?;
    let time_part = parts[date_part_idx + 3];

    let month = months
        .iter()
        .find(|(m, _)| *m == month_name)
        .map(|(_, n)| *n)?;

    let time_parts: Vec<&str> = time_part.split(':').collect();
    if time_parts.len() != 3 {
        return None;
    }

    let hour: u32 = time_parts[0].parse().ok()?;
    let minute: u32 = time_parts[1].parse().ok()?;
    let second: u32 = time_parts[2].parse().ok()?;

    // 计算从 1970-01-01 到目标日期的天数
    let days_since_epoch = days_since_1970(year, month, day);

    let total_seconds =
        days_since_epoch * 86400 + hour as u64 * 3600 + minute as u64 * 60 + second as u64;

    Some(total_seconds)
}

/// 计算从 1970-01-01 到指定日期的天数
fn days_since_1970(year: i32, month: u32, day: u32) -> u64 {
    let mut days = 0i64;

    // 计算完整年份的天数
    for y in 1970..year {
        days += if is_leap_year(y) { 366 } else { 365 };
    }

    // 计算当年月份的天数
    let month_days = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for m in 1..month {
        days += month_days[(m - 1) as usize] as i64;
        if m == 2 && is_leap_year(year) {
            days += 1;
        }
    }

    // 加上当月的天数
    days += (day - 1) as i64;

    days as u64
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}
