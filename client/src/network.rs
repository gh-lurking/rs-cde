// src/network.rs — 联网激活 + 校验（使用 ureq 同步 HTTP 客户端）
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

#[derive(Serialize)]
struct VerifyRequest {
    key_hash: String,  // SHA256(HKEY)，不发送明文
    timestamp: u64,    // 当前 Unix 时间（防重放）
    signature: String, // HMAC-SHA256(key_hash + timestamp)
}

#[derive(Deserialize)]
pub struct VerifyResponse {
    pub activation_ts: u64, // 服务器记录的激活时间戳
    pub revoked: bool,      // 是否已吊销
    pub expires_at: u64,    // 过期时间戳
}

/// 计算 SHA256(hkey) → hex string（不发送明文）
fn hash_key(hkey: &str) -> String {
    let mut h = Sha256::new();
    h.update(hkey.as_bytes());
    format!("{:x}", h.finalize())
}

/// 生成请求签名：HMAC-SHA256(secret=hkey, msg="key_hash|timestamp")
fn sign_request(hkey: &str, key_hash: &str, ts: u64) -> String {
    let mut mac = HmacSha256::new_from_slice(hkey.as_bytes()).unwrap();
    mac.update(key_hash.as_bytes());
    mac.update(b"|");
    mac.update(ts.to_string().as_bytes());
    format!("{:x}", mac.finalize().into_bytes())
}

/// 联网校验：POST /verify，超时返回 Err 后降级到本地校验
pub fn verify_online(
    hkey: &str,
    server_url: &str,
    timeout_secs: u64,
) -> Result<VerifyResponse, String> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
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

/// 首次激活：POST /activate（仅当本地无记录时调用）
pub fn activate_online(hkey: &str, server_url: &str) -> Result<u64, String> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let key_hash = hash_key(hkey);
    let signature = sign_request(hkey, &key_hash, ts);

    #[derive(Serialize)]
    struct ActivateReq {
        key_hash: String,
        timestamp: u64,
        signature: String,
    }

    #[derive(Deserialize)]
    struct ActivateResp {
        activation_ts: u64,
    }

    let url = format!("{}/activate", server_url);
    let resp = ureq::post(&url)
        .timeout(std::time::Duration::from_secs(5))
        .send_json(&ActivateReq {
            key_hash,
            timestamp: ts,
            signature,
        })
        .map_err(|e| e.to_string())?;

    let r: ActivateResp = resp.into_json().map_err(|e| e.to_string())?;
    Ok(r.activation_ts)
}
