// src/geo_check.rs
//
// 两种检测策略的实现

use reqwest::{Client, ClientBuilder};
use std::net::Ipv4Addr;
use std::time::Duration;
// use serde::Deserialize;
use crate::cn_cidr::CN_CIDR_LIST;

// ─── HTTP 客户端构建 ────────────────────────────────────────────────────────

/// 构建统一 HTTP 客户端：超时 8 秒，User-Agent 伪装为常规浏览器
pub fn build_http_client() -> Client {
    ClientBuilder::new()
        .timeout(Duration::from_secs(8))
        .user_agent(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
             AppleWebKit/537.36 (KHTML, like Gecko) \
             Chrome/124.0.0.0 Safari/537.36",
        )
        .build()
        .expect("Failed to build http client")
}

// ─── 策略 1: 公网出口 IP 获取 + 内置 CN CIDR 表匹配 ────────────────────────
//
// ❌ 错误做法（原始 bug）：
//    读取本机网络接口 IP（如 eth0: 192.168.1.5, lo: 127.0.0.1）
//    这些全是 RFC1918 私有/回环地址，永远不会命中公网 CN CIDR 段！
//
// ✅ 正确做法：
//    通过公开探针端点获取 NAT 后的真实公网出口 IP，再与 CIDR 比对。
//    使用 https://whatismyip.akamai.com/ —— Akamai 全球边缘节点，
//    直接返回纯文本公网 IP，响应极快（通常 < 100ms）。

const AKAMAI_WHATISMYIP_URL: &str = "https://whatismyip.akamai.com/";

/// 通过 Akamai 探针获取真实公网出口 IP，再与内置 CN CIDR 表比对
pub async fn check_public_ip_cidr(client: Client) -> Result<bool, String> {
    // Step 1: 获取公网 IP（纯文本响应，如 "1.2.3.4\n"）
    let resp = client
        .get(AKAMAI_WHATISMYIP_URL)
        .send()
        .await
        .map_err(|e| format!("Failure with public IP request: {e}"))?;
    // .map_err(|_| format!("ERR-REQ-I"))?;

    let body = resp
        .text()
        .await
        .map_err(|e| format!("Failure with public IP response: {e}"))?;
    // .map_err(|_| format!("ERR-RESPONSE-I}"))?;

    let ip_str = body.trim();
    println!("  → Public IP: {ip_str}");

    // Step 2: 解析为 Ipv4Addr（暂不处理 IPv6，CN 检测以 IPv4 为主）
    let ipv4: Ipv4Addr = ip_str
        .parse()
        .map_err(|_| format!("Public IP Resolution Failure : '{ip_str}' (SKIPPED)"))?;

    // Step 3: 与内置 CN CIDR 表比对
    if is_cn_ip(&ipv4) {
        println!("  → {ipv4} CN MATCH");
        Ok(true)
    } else {
        Ok(false)
    }
}

/// CIDR 匹配：将 IPv4 转为 u32，按 prefix_len 掩码比较
/// ✅ BUG-FIX: 修复 CIDR 匹配的位运算溢出
pub fn is_cn_ip(ip: &Ipv4Addr) -> bool {
    let ip_u32 = u32::from(*ip);
    for &(base, prefix_len) in CN_CIDR_LIST {
        // 显式处理边界情况
        if prefix_len == 0 {
            return true; // 0.0.0.0/0 匹配所有
        }

        let mask = if prefix_len >= 32 {
            u32::MAX // 全 1 掩码
        } else {
            // 安全的位移操作 (1..=31)
            !0u32.checked_shl(32 - prefix_len as u32).unwrap_or(0)
        };

        if (ip_u32 & mask) == (base & mask) {
            return true;
        }
    }
    false
}

// ─── 策略 2: Cloudflare /cdn-cgi/trace ──────────────────────────────────────
//
// 响应格式（纯文本 key=value，每行一条）:
//   fl=xxxx
//   h=cloudflare.com
//   ip=1.2.3.4
//   ts=1234567890.123
//   visit_scheme=https
//   uag=Mozilla/5.0 ...
//   colo=SJC
//   sliver=none
//   http=http/2
//   loc=US          ← 我们关注这一行
//   tls=TLSv1.3
//   sni=plaintext
//   warp=off
//   gateway=off
//   rbi=off
//   kex=X25519

const CF_TRACE_URL: &str = "https://cloudflare.com/cdn-cgi/trace";

/// 请求 Cloudflare trace 端点，解析 loc= 字段
pub async fn check_cloudflare_trace(client: Client) -> Result<bool, String> {
    let resp = client
        .get(CF_TRACE_URL)
        .send()
        .await
        .map_err(|e| format!("CF Request Failure: {e}"))?;
    // .map_err(|_| format!("ERR-REQ-CF"))?;

    let body = resp
        .text()
        .await
        .map_err(|e| format!("CF Response Failure: {e}"))?;
    // .map_err(|_| format!("ERR-RESPONSE-CF"))?;

    // 解析 loc= 字段
    let loc = parse_kv_field(&body, "loc");

    match loc.as_deref() {
        Some("CN") => {
            println!("  → track: loc=CN");
            Ok(true)
        }
        Some(code) => {
            println!("  → track: loc={code}");
            Ok(false)
        }
        None => Err("loc failure".to_string()),
    }
}

// ─── 辅助函数 ────────────────────────────────────────────────────────────────
/// 从 key=value 格式文本中提取指定 key 的值
fn parse_kv_field(text: &str, key: &str) -> Option<String> {
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix(&format!("{key}=")) {
            return Some(rest.trim().to_string());
        }
    }
    None
}
