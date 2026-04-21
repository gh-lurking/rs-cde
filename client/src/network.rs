// client/src/network.rs — 优化版 v3
//
// ✅ M-01 FIX: server_id 编译期硬编码
// ✅ MD-01 FIX: SNTP 时间校正公式
// ✅ M-03 FIX: validate_system_time 阈值改为 300s
// ✅ BUG-07 FIX: 重试时 one_way_delay 上界钳制，改善 RTT 不对称场景
// ✅ BUG-09 FIX: 优先使用 CF trace ts= 字段（毫秒精度）

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<sha2::Sha256>;

const MAX_CLOCK_OFFSET_SECS: i64 = 300;
const NET_DEFAULT_TIMEOUT_SECS: u64 = 10;
const SYSTEM_TIME_HARD_LIMIT_SECS: i64 = 300;
const SYSTEM_TIME_WARN_SECS: i64 = 60;

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

// ✅ M-01 FIX: 编译期确定，不再动态网络拉取
fn get_server_id() -> &'static str {
    static ID: OnceLock<String> = OnceLock::new();
    ID.get_or_init(|| {
        option_env!("BUILD_SERVER_ID")
            .unwrap_or("license-server-v1")
            .to_string()
    })
}

static HTTP_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

fn get_http_client() -> &'static reqwest::Client {
    HTTP_CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(NET_DEFAULT_TIMEOUT_SECS))
            .tcp_keepalive(Duration::from_secs(60))
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
    let server_id = get_server_id();
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
        403 => {
            return match err_code {
                "ERR-REVOKED" | "key revoked" => ERR_REVOKED.to_string(),
                "ERR-INVALID-KEY" | "invalid key" => ERR_INVALID_KEY.to_string(),
                "ERR-NOT-ACTIVATED" | "not activated" => ERR_NOT_ACTIVATED.to_string(),
                _ => format!("ERR-FORBIDDEN:{}", err_code),
            }
        }
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

async fn do_verify(hkey: &str, server_url: &str, ts: i64) -> Result<VerifyResponse, String> {
    let key_hash = hash_key(hkey);
    let signature = sign_request(hkey, &key_hash, ts);
    let req = VerifyRequest {
        key_hash,
        timestamp: ts,
        signature,
    };
    let url = format!("{}/verify", server_url);
    let resp = get_http_client()
        .post(&url)
        .json(&req)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.map_err(|e| format!("JSON decode: {e}"))?;
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
            let server_ts: i64 = e
                .trim_start_matches("ERR-TIME-RECORD:server_time=")
                .parse()
                .unwrap_or(t1);
            let t4 = now_secs();
            let full_rtt = t4 - t1;

            if full_rtt < 0 || full_rtt > NET_DEFAULT_TIMEOUT_SECS as i64 * 2 {
                tracing::warn!("[Network] 不合理的 RTT: {}s", full_rtt);
                return result;
            }

            // ✅ BUG-07 FIX: one_way_delay 上界钳制，防非对称 RTT 估算过大
            let one_way_delay = (full_rtt / 2).max(0).min(NET_DEFAULT_TIMEOUT_SECS as i64);
            let estimated_server_now = server_ts + one_way_delay;
            let clock_offset = t1 - estimated_server_now;

            tracing::info!(
                "[Network] RTT={}s one_way={}s local={} server={} estimated_server={}",
                full_rtt,
                one_way_delay,
                t1,
                server_ts,
                estimated_server_now
            );

            if clock_offset.abs() > MAX_CLOCK_OFFSET_SECS {
                return Err(format!("ERR-CLOCK-SKEW:{}", clock_offset));
            }

            // 用估算的服务端当前时间重试
            let retry = do_verify(hkey, server_url, estimated_server_now).await;
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

/// ✅ BUG-09 FIX: 优先使用 CF trace ts= 字段（毫秒精度，非 CDN 缓存）
pub async fn validate_system_time() -> Result<(), String> {
    let local_now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let min_ts: u64 = 1_704_067_200; // 2024-01-01
    let max_ts: u64 = 1_893_456_000; // 2030-01-01
    if local_now < min_ts || local_now > max_ts {
        return Err("系统时间超出合理范围 (2024-2030)".into());
    }

    let client = get_http_client();
    let mut valid_checks = 0i64;
    let mut total_offset = 0i64;

    // ✅ 优先：Cloudflare trace ts= 字段（Unix 浮点秒，精度高，非缓存）
    if let Some(cf_ts) = get_time_from_cf_trace(client).await {
        total_offset += local_now as i64 - cf_ts;
        valid_checks += 1;
        tracing::info!("[Time] CF trace ts={}, local={}", cf_ts, local_now);
    }

    // 降级：HTTP Date 头（精度 1s，CDN 可能有缓存延迟）
    let http_sources = ["https://www.google.com", "https://www.microsoft.com"];
    for url in http_sources {
        if let Ok(resp) = client
            .head(url)
            .timeout(Duration::from_secs(5))
            .send()
            .await
        {
            if let Some(date) = resp.headers().get("date") {
                if let Ok(date_str) = date.to_str() {
                    if let Some(server_time) = parse_http_date_to_timestamp(date_str) {
                        total_offset += local_now as i64 - server_time as i64;
                        valid_checks += 1;
                    }
                }
            }
        }
    }

    if valid_checks == 0 {
        tracing::warn!("[Time] 无法访问任何时间源，跳过 HTTPS 检查");
        return Ok(());
    }

    let avg_offset = total_offset / valid_checks;

    if avg_offset.abs() > SYSTEM_TIME_HARD_LIMIT_SECS {
        return Err(format!(
            "系统时间偏差 {}s 超过限制 {}s，请同步时钟",
            avg_offset, SYSTEM_TIME_HARD_LIMIT_SECS
        ));
    }
    if avg_offset.abs() > SYSTEM_TIME_WARN_SECS {
        tracing::warn!(
            "[Time] 时间偏差 {}s > {}s 警告阈值",
            avg_offset,
            SYSTEM_TIME_WARN_SECS
        );
    }
    Ok(())
}

/// 从 Cloudflare /cdn-cgi/trace 获取 ts= 字段（精度高，非缓存）
async fn get_time_from_cf_trace(client: &reqwest::Client) -> Option<i64> {
    let resp = client
        .get("https://cloudflare.com/cdn-cgi/trace")
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .ok()?;
    let body = resp.text().await.ok()?;
    for line in body.lines() {
        if let Some(ts_str) = line.strip_prefix("ts=") {
            // ts 格式: "1700000000.123"（Unix 浮点秒）
            let ts: f64 = ts_str.trim().parse().ok()?;
            return Some(ts as i64);
        }
    }
    None
}

fn parse_http_date_to_timestamp(date_str: &str) -> Option<u64> {
    let parts: Vec<&str> = date_str.split_whitespace().collect();
    if parts.len() < 6 {
        return None;
    }
    let day: u32 = parts[1].parse().ok()?;
    let month: u32 = match parts[2] {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let year: i32 = parts[3].parse().ok()?;
    let tp: Vec<&str> = parts[4].split(':').collect();
    if tp.len() != 3 {
        return None;
    }
    let h: u32 = tp[0].parse().ok()?;
    let m: u32 = tp[1].parse().ok()?;
    let s: u32 = tp[2].parse().ok()?;
    let days = days_since_1970(year, month, day);
    Some(days * 86400 + h as u64 * 3600 + m as u64 * 60 + s as u64)
}

fn days_since_1970(year: i32, month: u32, day: u32) -> u64 {
    let mut days = 0i64;
    for y in 1970..year {
        days += if is_leap_year(y) { 366 } else { 365 };
    }
    let md = [31u32, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for m in 1..month {
        days += md[(m - 1) as usize] as i64;
        if m == 2 && is_leap_year(year) {
            days += 1;
        }
    }
    days += (day - 1) as i64;
    days as u64
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}
