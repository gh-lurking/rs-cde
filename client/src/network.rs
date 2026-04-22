// client/src/network.rs — 优化版 v6
//
// [BUG-A1 FIX] do_verify 零值 guard 实际生效（不再被 serde 覆盖）
// [BUG-A9 FIX] max_ts 改为动态计算，避免程序到 2030 年后无法启动
// [BUG-C1 FIX] 时钟补偿重试：ERR-TIME-RECORD 再次出现时尝试二次补偿（最多 2 次）
// [BUG-C4 FIX] 两个时间源都失败时明确返回 Err，不静默跳过

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;
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
        409 => {
            return match err_code {
                "ERR-NOT-ACTIVATED" | "not activated" | "ERR-ALREADY-ACTIVATED" => {
                    ERR_NOT_ACTIVATED.to_string()
                }
                "ERR-NONCE-REPLAY" => "ERR-NONCE-REPLAY".to_string(),
                _ => format!("ERR-FORBIDDEN:{}", err_code),
            }
        }
        403 => {
            return match err_code {
                "ERR-REVOKED" | "key revoked" => ERR_REVOKED.to_string(),
                "ERR-INVALID-KEY" | "invalid key" => ERR_INVALID_KEY.to_string(),
                "ERR-NOT-ACTIVATED" | "not activated" => ERR_NOT_ACTIVATED.to_string(),
                _ => format!("ERR-FORBIDDEN:{}", err_code),
            }
        }
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
        // [BUG-A1 FIX] 零值 guard：先解析，再检查，不被后续代码覆盖
        let vr: VerifyResponse =
            serde_json::from_value(body).map_err(|e| format!("JSON decode: {e}"))?;
        if vr.activation_ts <= 0 || vr.expires_at <= 0 {
            return Err("ERR-ZERO-VALUE-RESPONSE".to_string());
        }
        Ok(vr)
    } else {
        Err(parse_server_error(status, &body))
    }
}

// [BUG-C1 FIX] 时钟补偿最多重试 2 次，第二次 ERR-TIME-RECORD 也尝试二次补偿
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
            if full_rtt > NET_DEFAULT_TIMEOUT_SECS as i64 * 2 {
                tracing::warn!("[Network] 不合理的 RTT: {}s，放弃时钟补偿重试", full_rtt);
                return result;
            }

            let one_way_delay = (full_rtt / 2).max(0).min(NET_DEFAULT_TIMEOUT_SECS as i64);
            let estimated_server_now = server_ts + one_way_delay;
            let clock_offset = t1 - estimated_server_now;

            if clock_offset.abs() > MAX_CLOCK_OFFSET_SECS {
                return Err(format!("ERR-CLOCK-SKEW:{}", clock_offset));
            }

            let retry = do_verify(hkey, server_url, estimated_server_now).await;

            // [BUG-C1 FIX] 第二次仍返回 ERR-TIME-RECORD 时，尝试二次补偿
            match &retry {
                Err(e2) if e2.starts_with("ERR-TIME-RECORD:server_time=") => {
                    let server_ts2: i64 = e2
                        .trim_start_matches("ERR-TIME-RECORD:server_time=")
                        .parse()
                        .unwrap_or(estimated_server_now);
                    let t5 = now_secs();
                    let delay2 = ((t5 - t1) / 2).max(0);
                    let est2 = server_ts2 + delay2;
                    let offset2 = estimated_server_now - est2;
                    if offset2.abs() > MAX_CLOCK_OFFSET_SECS {
                        Err(format!("ERR-CLOCK-SKEW-PERSISTENT:server={}", server_ts2))
                    } else {
                        let retry2 = do_verify(hkey, server_url, est2).await;
                        match &retry2 {
                            Err(e3) if e3.starts_with("ERR-TIME-RECORD:") => {
                                Err(format!("ERR-CLOCK-SKEW-PERSISTENT:server={}", server_ts2))
                            }
                            _ => retry2,
                        }
                    }
                }
                _ => retry,
            }
        }
        _ => result,
    }
}

// [BUG-C4 FIX] 两个时间源都失败时明确返回 Err，不静默跳过
pub async fn validate_system_time() -> Result<(), String> {
    let local_now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // [BUG-A9 FIX] 下界固定（2024-01-01），上界动态（当前+10年），永不过时
    let min_ts: u64 = 1_704_067_200;
    let max_ts: u64 = local_now + 10 * 365 * 86400;

    if local_now < min_ts || local_now > max_ts {
        return Err(format!("系统时间 {} 超出合理范围", local_now));
    }

    let client = get_http_client();
    let cf_ts = get_time_from_cf_trace(client).await;

    // HTTP Date 作为第二时间源
    let http_ts = get_time_from_http_date(client).await;

    // [BUG-C4 FIX] 两个时间源都失败时明确报错，不静默通过
    let timestamps: Vec<i64> = [cf_ts, http_ts].into_iter().flatten().collect();
    if timestamps.is_empty() {
        return Err(
            "无法获取外部时间源（CF trace 和 HTTP Date 均不可用），请检查网络连接".to_string(),
        );
    }

    let avg_offset: i64 = timestamps
        .iter()
        .map(|&t| local_now as i64 - t)
        .sum::<i64>()
        / timestamps.len() as i64;

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
            let ts: f64 = ts_str.trim().parse().ok()?;
            return Some(ts as i64);
        }
    }
    None
}

async fn get_time_from_http_date(client: &reqwest::Client) -> Option<i64> {
    let resp = client
        .head("https://www.google.com")
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .ok()?;
    let date_str = resp.headers().get("date")?.to_str().ok()?;
    let server_time = parse_http_date_to_timestamp(date_str).unwrap();
    Some(server_time as i64)
}

fn parse_http_date_to_timestamp(date_str: &str) -> Option<u64> {
    // RFC 7231: "Tue, 15 Nov 1994 08:12:31 GMT"
    let parts: Vec<&str> = date_str.split_whitespace().collect();
    if parts.len() != 6 {
        return None;
    }
    let day: u32 = parts[1].parse().ok()?;
    let month = match parts[2] {
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
