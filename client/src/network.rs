// client/src/network.rs — 最终优化版
// BUG-G   FIX: 收到 ERR-TIME-RECORD 时，提取服务端时间自动重试一次
// BUG-J   FIX: 全局单例 Client，连接池跨调用复用（OnceLock 线程安全）
// BUG-NEW-6 FIX: get_http_client 移除 timeout_secs 参数，接口诚实（OnceLock 首次调用固化）
// BUG-NEW-7 FIX: 时钟偏差修正加上限（±600s），防止恶意服务端操纵本地时间感知

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

/// BUG-NEW-7 FIX: 时钟偏差安全阈值（±600s = ±10分钟）
const MAX_CLOCK_OFFSET_SECS: i64 = 600;

/// BUG-NEW-6 FIX: 超时常量化，不再作为参数传入 get_http_client
const NET_DEFAULT_TIMEOUT_SECS: u64 = 10;

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

/// BUG-NEW-6 FIX: 移除 timeout_secs 参数
/// OnceLock 只初始化一次，参数传入毫无意义——接口应诚实反映这一约束
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

/// BUG-G FIX: 支持时间偏移的单次请求（ts_offset 用于时钟修正重试）
async fn do_verify(
    hkey: &str,
    server_url: &str,
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

    // BUG-J FIX + BUG-NEW-6 FIX: 使用无参数版本的 get_http_client
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

/// 主入口：在线校验
/// BUG-G   FIX: 自动时钟修正（收到 ERR-TIME-RECORD 时重试一次）
/// BUG-J   FIX: 全局 Client 单例
/// BUG-NEW-6 FIX: timeout_secs 参数保留但仅供文档参考（实际由常量控制）
///               NOTE: 参数已移除，调用处无需传入
/// BUG-NEW-7 FIX: 时钟偏差超过 MAX_CLOCK_OFFSET_SECS 时拒绝修正并返回错误
pub async fn verify_online(
    hkey: &str,
    server_url: &str,
    // timeout_secs 参数已移除（BUG-NEW-6 FIX）
) -> Result<VerifyResponse, String> {
    let result = do_verify(hkey, server_url, 0).await;

    match &result {
        Err(e) if e.starts_with("ERR-TIME-RECORD:server_time=") => {
            let server_time_str = e.trim_start_matches("ERR-TIME-RECORD:server_time=");
            if let Ok(server_ts) = server_time_str.parse::<i64>() {
                let offset = server_ts - now_secs();

                // BUG-NEW-7 FIX: 偏差超过阈值时拒绝修正
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

                tracing::warn!("[License] 时钟偏差 {}s，自动修正后重试", offset);
                return do_verify(hkey, server_url, offset).await;
            }
            result
        }
        _ => result,
    }
}
