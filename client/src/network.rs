// client/src/network.rs — 优化版（修复 BUG-06: 删除死代码 activate_online）

//

// BUG-06 FIX: 移除从未被调用的 activate_online()；

//             统一使用 ureq 同步 HTTP，无需与 tokio/reqwest 共存

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

/// 服务端 /verify 响应结构
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

/// 联网校验：POST /verify

/// 超时或网络错误返回 Err，调用方降级到纯本地校验

pub fn verify_online(
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

    let resp = ureq::post(&url)
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .send_json(&req)
        .map_err(|e| e.to_string())?;

    resp.into_json::<VerifyResponse>()
        .map_err(|e| e.to_string())
}

// BUG-06 FIX: activate_online() 已删除（死代码）
// 激活流程由服务端 /activate 接口处理，客户端首次运行时应引导用户
// 通过外部工具或初始化脚本完成激活，不在 license_guard 主流程中调用