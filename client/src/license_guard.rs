// src/license_guard.rs — 核心校验逻辑
use std::collections::HashSet;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use obfstr::obfstr;    // 编译期混淆字符串常量

use crate::storage;
use crate::network;

/// 授权秘钥集合（生产环境替换为实际值）
static VALID_KEYS: OnceLock<HashSet<&'static str>> = OnceLock::new();

fn valid_keys() -> &'static HashSet<&'static str> {
    VALID_KEYS.get_or_init(|| {
        // 生产环境：替换为真实的授权 key 列表
        [
            "HKEY-AAAA-1111-XXXX",
            "HKEY-BBBB-2222-YYYY",
            "HKEY-CCCC-3333-ZZZZ",
        ].into_iter().collect()
    })
}

/// 过期时长：365 天（秒）
const EXPIRE_SECS: u64 = 365 * 24 * 3600;

/// 联网超时：3 秒，超时后降级为纯本地校验
const NET_TIMEOUT_SECS: u64 = 3;

/// 主校验入口 —— 任何校验失败直接 exit(1)
pub fn check_and_enforce() {
    // ── Step 1: 读取并校验 HKEY ──────────────────────────
    let hkey = std::env::var("HKEY").unwrap_or_else(|_| {
        eprintln!("[License] 未设置 HKEY 环境变量，程序终止");
        std::process::exit(1);
    });

    if !valid_keys().contains(hkey.as_str()) {
        eprintln!("[License] 无效的授权秘钥，程序终止");
        std::process::exit(1);
    }

    // ── Step 2: obfstr 派生 SALT（编译期混淆）────────────
    // obfstr! 宏在编译期加密字符串，运行时才还原，
    // 逆向分析者无法在二进制中直接搜到明文 SALT
    let salt = obfstr!("PROG_ACTIVATION_SALT_V1_SECRET").to_owned();
    let server_url = obfstr!("https://your-license-server.com").to_owned();

    // ── Step 3: 读取三重本地存储 ─────────────────────────
    let local_ts = storage::read_activation_ts(&hkey, &salt);

    // ── Step 4: 联网校验（主要路径）──────────────────────
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH).unwrap().as_secs();

    match network::verify_online(&hkey, &server_url, NET_TIMEOUT_SECS) {
        Ok(resp) => {
            // 服务器明确返回：已吊销
            if resp.revoked {
                eprintln!("[License] 授权已被吊销，程序终止");
                std::process::exit(1);
            }

            let server_ts = resp.activation_ts;

            // 服务器时间校验
            if now.saturating_sub(server_ts) > EXPIRE_SECS {
                let days = (now - server_ts) / 86400;
                eprintln!("[License] 授权已过期 {} 天（服务器时间），程序终止", days - 365);
                std::process::exit(1);
            }

            // 以服务器时间为权威，修复/同步本地三个副本
            storage::write_all_replicas(&hkey, &salt, server_ts);

            println!(
                "[License] ✅ 在线校验通过，剩余 {} 天",
                (EXPIRE_SECS.saturating_sub(now - server_ts)) / 86400
            );
        }

        Err(e) => {
            // 联网失败 → 降级为纯本地校验
            eprintln!("[License] 联网校验失败（{}），回退到本地校验", e);

            let ts = local_ts.unwrap_or_else(|| {
                eprintln!("[License] 本地无激活记录且无法联网，程序终止");
                std::process::exit(1);
            });

            // 时钟回拨检测
            if now < ts {
                eprintln!("[License] 检测到系统时钟回拨，程序终止");
                std::process::exit(1);
            }

            if now - ts > EXPIRE_SECS {
                let days = (now - ts) / 86400;
                eprintln!("[License] 授权已过期 {} 天（本地时间），程序终止", days - 365);
                std::process::exit(1);
            }

            println!(
                "[License] ✅ 本地校验通过（离线模式），剩余约 {} 天",
                (EXPIRE_SECS.saturating_sub(now - ts)) / 86400
            );
        }
    }
}