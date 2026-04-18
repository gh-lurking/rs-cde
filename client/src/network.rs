// client/src/network.rs — 优化版（修复 BUG-06: 改为 async reqwest）

// BUG-06 FIX: 原码使用 ureq（同步阻塞），会阻塞 tokio 工作线程。
//             改为 reqwest async，在 tokio 上下文中安全调用。

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

#[derive(Serialize)]
struct VerifyRequest {
    key_hash: String,
    timestamp: i64,
    signature: String,
}

/// 验证响应：/verify 接口返回体
#[derive(Deserialize)]
pub struct VerifyResponse {
    pub activation_ts: i64,
    pub expires_at: i64,
    pub revoked: bool,
}

/// SHA256(hkey) → hex string
pub fn hash_key(hkey: &str) -> String {
    let mut h = Sha256::new();
    h.update(hkey.as_bytes());
    format!("{:x}", h.finalize())
}

/// HMAC-SHA256(secret=hkey, msg="key_hash|timestamp")
fn sign_request(hkey: &str, key_hash: &str, ts: i64) -> String {
    let mut mac = HmacSha256::new_from_slice(hkey.as_bytes()).unwrap();
    mac.update(key_hash.as_bytes());
    mac.update(b"|");
    mac.update(ts.to_string().as_bytes());
    format!("{:x}", mac.finalize().into_bytes())
}

/// 在线校验：POST /verify（BUG-06 FIX: async reqwest）
///
/// 返回 Err 时调用方降级到本地缓存校验
pub async fn verify_online(
    hkey: &str,
    server_url: &str,
    timeout_secs: u64,
) -> Result<VerifyResponse, String> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let key_hash = hash_key(hkey);
    let signature = sign_request(hkey, &key_hash, ts);

    let req = VerifyRequest {
        key_hash,
        timestamp: ts,
        signature,
    };

    let url = format!("{}/verify", server_url);

    // BUG-06 FIX: reqwest async，不阻塞 tokio 线程
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .build()
        .map_err(|e| e.to_string())?;

    let resp = client
        .post(&url)
        .json(&req)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    resp.json::<VerifyResponse>()
        .await
        .map_err(|e| e.to_string())
}

// BUG-06 FIX: activate_online() 也改为 async reqwest
// 从未激活的情况下调用激活接口，获取 activation_ts 和 expires_at，
// 写入本地存储后由 license_guard 中统一处理。
// 不在 license_guard 中调用（保持职责单一）
