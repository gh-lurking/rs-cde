// client/src/license_guard.rs — 优化版 v3
//
// ✅ C-01 FIX: 离线模式先零值检查，再过期检查（顺序正确）
// ✅ BUG-10: 确认所有错误分支均有明确的退出路径

use crate::{network, storage, time_guard};
use obfstr::obfstr;
use std::time::{SystemTime, UNIX_EPOCH};

pub async fn check_and_enforce() {
    let hkey = std::env::var("HKEY").unwrap_or_else(|_| {
        eprintln!("[License] 未提供 HKEY 环境变量");
        std::process::exit(1);
    });

    let salt = obfstr!("PROG_ACTIVATION_SALT_V1_SECRET").to_owned();
    let server_url = obfstr!("https://license.example.com").to_owned();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    match network::verify_online(&hkey, &server_url).await {
        // ─── 在线成功路径 ───────────────────────────────────────────────
        Ok(resp) => {
            if resp.revoked {
                eprintln!("[License] 服务端返回 revoked=true");
                std::process::exit(1);
            }
            if resp.activation_ts <= 0 || resp.expires_at <= 0 {
                eprintln!("[License] 服务端返回无效记录");
                std::process::exit(1);
            }
            if resp.activation_ts > now + 300 {
                eprintln!("[License] activation_ts 在未来，可能存在时钟篡改");
                std::process::exit(1);
            }
            if resp.activation_ts >= resp.expires_at {
                eprintln!("[License] 数据异常: activation_ts >= expires_at");
                std::process::exit(1);
            }
            if now >= resp.expires_at {
                let days = (now - resp.expires_at) / 86400;
                eprintln!("[License] 密钥已过期 {} 天", days);
                std::process::exit(1);
            }
            let remaining = (resp.expires_at - now) / 86400;
            println!("[License] 在线验证通过，剩余 {} 天", remaining);

            storage::write_all_replicas(
                &hkey,
                &salt,
                resp.activation_ts as u64,
                resp.expires_at as u64,
            );
            time_guard::set_expiry_time(resp.expires_at);
        }

        // ─── 网络失败路径 ───────────────────────────────────────────────
        Err(ref e) => {
            // 服务端明确拒绝的错误 → 不走离线降级，直接退出
            if e == network::ERR_REVOKED {
                eprintln!("[License] 密钥已被撤销");
                std::process::exit(1);
            }
            if e == network::ERR_INVALID_KEY {
                eprintln!("[License] 无效密钥");
                std::process::exit(1);
            }
            if e == network::ERR_NOT_ACTIVATED {
                eprintln!("[License] 密钥未激活");
                std::process::exit(1);
            }
            if e == network::ERR_EXPIRED {
                eprintln!("[License] 密钥已过期（服务端）");
                std::process::exit(1);
            }
            if e.starts_with("ERR-FORBIDDEN:") {
                eprintln!("[License] 地区受限");
                std::process::exit(1);
            }
            if e.starts_with("ERR-CLOCK-SKEW-PERSISTENT:") {
                eprintln!("[License] 持续性时钟偏移，请同步系统时间");
                std::process::exit(1);
            }

            eprintln!("[License] 在线验证失败 ({}), 尝试本地缓存...", e);

            match storage::read_local_record(&hkey, &salt) {
                storage::LocalReadResult::Insufficient { read_count } => {
                    eprintln!("[License] 本地副本不足 ({}/3)", read_count);
                    std::process::exit(1);
                }
                storage::LocalReadResult::Tampered { read_count } => {
                    eprintln!("[License] 本地副本被篡改 ({}/3)", read_count);
                    std::process::exit(1);
                }
                storage::LocalReadResult::Success {
                    value: (local_ts, local_expires),
                    read_count: _,
                    repair_failed,
                } => {
                    if repair_failed {
                        eprintln!("[License] 副本修复失败，请注意");
                    }

                    // ✅ C-01 FIX 步骤 1：先做零值检查
                    if local_ts == 0 || local_expires == 0 {
                        eprintln!("[License] 本地记录损坏（零值）");
                        std::process::exit(1);
                    }

                    // ✅ C-01 FIX 步骤 2：再做过期检查
                    if now >= local_expires as i64 {
                        let days = (now - local_expires as i64) / 86400;
                        eprintln!("[License] 密钥已过期 {} 天（离线）", days);
                        std::process::exit(1);
                    }

                    if local_ts as i64 > now + 300 {
                        eprintln!("[License] activation_ts 在未来（可能被篡改）");
                        std::process::exit(1);
                    }
                    if local_ts >= local_expires {
                        eprintln!("[License] 本地记录损坏（ts >= exp）");
                        std::process::exit(1);
                    }

                    let remaining = (local_expires as i64 - now) / 86400;
                    println!("[License] 离线验证通过，剩余 {} 天", remaining);
                    time_guard::set_expiry_time(local_expires as i64);
                }
            }
        }
    }
}
