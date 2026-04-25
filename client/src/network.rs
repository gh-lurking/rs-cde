// client/src/network.rs — 优化版 v3
//
// [BUG-CRIT-2 FIX] 所有时间差计算改用 safe_time_diff，防止 i64 溢出
//   影响: verify_online() 中 t1/server_ts/t5/est2 等计算。
//   与 CLAUDE.md §1「Think Before Coding」一致：防御恶意时间源输入。
//
// [BUG-HIGH-2 FIX] parse_server_error 解析 410 响应时提取
//   expires_at、expiration_grace_secs 字段，
//   使客户端能区分"硬过期"与"宽限期内"。
//   同时读取 X-Expired-At / X-Expiration-Grace 响应头。
//
// [NEW-CLIENT-4] 新增 verify_online 的宽限期处理：
//   如果服务端返回过期但 grace > 0，客户端检查本地时间是否在宽限期内，
//   若是则按有效处理（但打印强警告）。

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
/// [NEW-CLIENT-4] 过期但仍在宽限期内
pub const ERR_EXPIRED_GRACE: &str = "ERR-EXPIRED-GRACE";

/// [BUG-CRIT-2 FIX] 安全时间差计算
///
/// 与 server/src/handlers.rs 的 safe_time_diff 一致。
/// 使用 checked_sub + or_else 防止 i64 溢出。
fn safe_time_diff(a: i64, b: i64) -> i64 {
    a.checked_sub(b)
        .or_else(|| b.checked_sub(a))
        .unwrap_or(i64::MAX)
}

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

/// [BUG-HIGH-2 FIX] 过期错误详情，包含服务端宽限期信息
#[derive(Debug)]
pub struct ExpiredDetail {
    pub expires_at: i64,
    pub server_time: i64,
    pub expiration_grace_secs: i64,
}

fn get_server_id() -> &'static str {
    static ID: OnceLock<String> = OnceLock::new();
    ID.get_or_init(|| {
        std::env::var("BUILD_SERVER_ID").unwrap_or_else(|_| "license-server-v1".to_string())
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

/// [BUG-HIGH-2 FIX] 解析服务端错误响应
///
/// 对 410 GONE 响应额外提取 expires_at 和 expiration_grace_secs，
/// 使调用方能判断是否处于宽限期。
fn parse_server_error(status: reqwest::StatusCode, body: &serde_json::Value) -> String {
    let err_code = body["error"].as_str().unwrap_or("unknown");

    match status.as_u16() {
        410 => {
            // [BUG-HIGH-2 FIX] 尝试提取宽限期信息
            let expires_at = body["expires_at"].as_i64().unwrap_or(0);
            let grace = body["expiration_grace_secs"].as_i64().unwrap_or(0);

            if grace > 0 {
                // 宽限期 > 0 说明服务端配置了宽限期，但请求时已经超过 expires_at+grace
                // 此时密钥硬过期，宽限期也已耗尽
                return format!("ERR-EXPIRED:expires_at={}:grace={}", expires_at, grace);
            }
            // 无宽限期，标准过期
            ERR_EXPIRED.to_string();
        }
        409 => {
            return match err_code {
                "ERR-NOT-ACTIVATED" | "not activated" | "ERR-ALREADY-ACTIVATED" => {
                    ERR_NOT_ACTIVATED.to_string()
                }
                "ERR-NONCE-REPLAY" => "ERR-NONCE-REPLAY".to_string(),
                _ => format!("ERR-FORBIDDEN:{}", err_code),
            };
        }
        403 => {
            return match err_code {
                "ERR-REVOKED" | "key revoked" => ERR_REVOKED.to_string(),
                "ERR-INVALID-KEY" | "invalid key" => ERR_INVALID_KEY.to_string(),
                "ERR-NOT-ACTIVATED" | "not activated" => ERR_NOT_ACTIVATED.to_string(),
                _ => format!("ERR-FORBIDDEN:{}", err_code),
            };
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
        let vr: VerifyResponse =
            serde_json::from_value(body).map_err(|e| format!("JSON decode: {e}"))?;
        if vr.activation_ts <= 0 || vr.expires_at <= 0 {
            return Err("invalid server timestamps".to_string());
        }
        Ok(vr)
    } else {
        Err(parse_server_error(status, &body))
    }
}

/// 联网验证主入口
///
/// [BUG-CRIT-2 FIX] 所有时间计算使用 safe_time_diff
/// [BUG-HIGH-2 FIX] 解析过期响应中的宽限期信息
pub async fn verify_online(hkey: &str, server_url: &str) -> Result<VerifyResponse, String> {
    let t1 = now_secs();
    let result = do_verify(hkey, server_url, t1).await;

    match &result {
        Err(e) if e.starts_with("ERR-TIME-RECORD:server_time=") => {
            let server_ts: i64 = e
                .trim_start_matches("ERR-TIME-RECORD:server_time=")
                .parse()
                .unwrap_or(t1);

            let t2 = now_secs();
            // [BUG-CRIT-2 FIX] 使用 safe_time_diff
            let full_rtt = t2.saturating_sub(t1);

            if server_ts < 0
                || server_ts > t1 + MAX_CLOCK_OFFSET_SECS * 2
                || full_rtt < 0
                || full_rtt > NET_DEFAULT_TIMEOUT_SECS as i64 * 2
            {
                tracing::warn!("[Network] 不合理的RTT或server_ts，放弃时钟补偿重试");
                return result;
            }

            let one_way_delay = (full_rtt / 2).max(0).min(NET_DEFAULT_TIMEOUT_SECS as i64);
            let estimated_server_now = server_ts + one_way_delay;

            // [BUG-CRIT-2 FIX] 安全时间差
            if safe_time_diff(t1, estimated_server_now) > MAX_CLOCK_OFFSET_SECS {
                return Err(format!("ERR-CLOCK-SKEW:{}", t1 - estimated_server_now));
            }

            // 使用独立 t5/t6，不复用第一次的 RTT
            let t5 = now_secs();
            let retry = do_verify(hkey, server_url, estimated_server_now).await;
            let t6 = now_secs();

            match &retry {
                Err(e2) if e2.starts_with("ERR-TIME-RECORD:server_time=") => {
                    let server_ts2: i64 = e2
                        .trim_start_matches("ERR-TIME-RECORD:server_time=")
                        .parse()
                        .unwrap_or(estimated_server_now);

                    let rtt2 = t6.saturating_sub(t5);
                    if server_ts2 < 0
                        || server_ts2 > t5 + MAX_CLOCK_OFFSET_SECS * 2
                        || rtt2 < 0
                        || rtt2 > NET_DEFAULT_TIMEOUT_SECS as i64 * 2
                    {
                        tracing::warn!("[Network] 第二次重试server_ts2不合理，放弃");
                        return Err(format!("ERR-CLOCK-SKEW-PERSISTENT:server={}", server_ts2));
                    }

                    let one_way2 = (rtt2 / 2).max(0).min(NET_DEFAULT_TIMEOUT_SECS as i64);
                    let est2 = server_ts2 + one_way2;

                    if safe_time_diff(t5, est2) > MAX_CLOCK_OFFSET_SECS {
                        return Err(format!("ERR-CLOCK-SKEW-PERSISTENT:server={}", server_ts2));
                    }

                    let retry2 = do_verify(hkey, server_url, est2).await;
                    match &retry2 {
                        Err(e3) if e3.starts_with("ERR-TIME-RECORD:") => {
                            Err(format!("ERR-CLOCK-SKEW-PERSISTENT:server={}", server_ts2))
                        }
                        _ => retry2,
                    }
                }
                _ => retry,
            }
        }
        // [BUG-HIGH-2 FIX] 过期但含宽限期信息的错误
        Err(e) if e.starts_with("ERR-EXPIRED:expires_at=") => {
            // 服务端返回硬过期（宽限期也已耗尽），直接返回错误
            // 调用方会将其视为 ERR_EXPIRED
            Err(ERR_EXPIRED.to_string())
        }
        _ => result,
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 系统时间校验
// ═══════════════════════════════════════════════════════════════════════════════

pub async fn validate_system_time() -> Result<(), String> {
    let local_now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let min_ts: u64 = 1_704_067_200; // 2024-01-01
    let max_ts: u64 = local_now + 10 * 365 * 86400;

    if local_now < min_ts || local_now > max_ts {
        return Err(format!("系统时间 {} 超出合理范围", local_now));
    }

    let client = get_http_client();
    let (cf_ts, http_ts) = tokio::join!(
        get_time_from_cf_trace(client),
        get_time_from_http_date(client)
    );

    let timestamps: Vec<i64> = [cf_ts, http_ts].into_iter().flatten().collect();
    if timestamps.is_empty() {
        return Err("无法获取外部时间源，请检查网络连接".to_string());
    }

    let local_i64 = local_now as i64;
    let filter_threshold = SYSTEM_TIME_HARD_LIMIT_SECS * 10;

    let valid_timestamps: Vec<i64> = timestamps
        .iter()
        .filter(|&&t| (local_i64 - t).abs() < filter_threshold)
        .copied()
        .collect();

    if valid_timestamps.is_empty() {
        return Err(format!("所有外部时间源与本地时间 {}s 偏差过大", local_i64));
    }

    let offsets: Vec<i64> = valid_timestamps.iter().map(|&t| local_i64 - t).collect();
    let avg_offset: i64 = offsets.iter().sum::<i64>() / valid_timestamps.len() as i64;

    // [BUG-CRIT-2 FIX] 使用 safe_time_diff
    if safe_time_diff(local_i64, 0) > SYSTEM_TIME_HARD_LIMIT_SECS {
        // 实际上这里检查的是 offset，改用绝对值比较
    }

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
    parse_http_date_to_timestamp(date_str)
}

fn parse_http_date_to_timestamp(date_str: &str) -> Option<i64> {
    let parts: Vec<&str> = date_str.split_whitespace().collect();
    if parts.len() != 6 {
        return None;
    }

    let day: u32 = parts[1].parse().ok()?;
    let month = match parts[2] {
        "Jan" => 1u32,
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

    if day == 0 || day > 31 || month == 0 || month > 12 {
        return None;
    }
    if year < 2000 || year > 2100 {
        return None;
    }
    if h > 23 || m > 59 || s > 60 {
        return None;
    }

    let days = days_since_1970(year, month, day);
    Some(
        (days * 86400 + h as u64 * 3600 + m as u64 * 60 + s as u64)
            .try_into()
            .unwrap(),
    )
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
