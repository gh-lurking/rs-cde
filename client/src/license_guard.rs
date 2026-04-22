// client/src/license_guard.rs
//
// [C-01 FIX]  activation_ts / expires_at 零值语义修正（在线 + 离线双路均检查）
// [BUG-01 FIX] 离线路径中增加零值检查
// [BUG-13 FIX] ERR_NOT_ACTIVATED / ERR_REVOKED / ERR_INVALID_KEY / ERR_EXPIRED 视为不可恢复
// [BUG-14 FIX] 服务端响应零值检查，防止空响应绕过验证

use crate::{network, storage, time_guard};
use obfstr::obfstr;
use std::time::{SystemTime, UNIX_EPOCH};

pub async fn check_and_enforce() {
    let hkey = std::env::var("HKEY").unwrap_or_else(|_| {
        eprintln!("[License] 未配置 HKEY 环境变量");
        std::process::exit(1);
    });

    let salt = obfstr!("PROG_ACTIVATION_SALT_V1_SECRET").to_owned();
    let server_url = obfstr!("https://license.example.com").to_owned();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    match network::verify_online(&hkey, &server_url).await {
        Ok(resp) => {
            // ── 在线验证成功：多重安全检查 ──────────────────────────────

            if resp.revoked {
                eprintln!("[License] 密钥已被吊销");
                std::process::exit(1);
            }

            // [C-01 FIX + BUG-14 FIX] 零值检查
            if resp.activation_ts <= 0 || resp.expires_at <= 0 {
                eprintln!("[License] 密钥字段无效（零值），请先激活密钥");
                std::process::exit(1);
            }

            // 防时钟篡改
            if resp.activation_ts > now + 300 {
                eprintln!("[License] activation_ts 在未来，可能时钟篡改");
                std::process::exit(1);
            }

            // 逻辑一致性检查
            if resp.activation_ts >= resp.expires_at {
                eprintln!("[License] 数据异常: activation_ts >= expires_at");
                std::process::exit(1);
            }

            // 过期检查
            if now >= resp.expires_at {
                let days = (now - resp.expires_at) / 86400;
                eprintln!("[License] 授权已过期 {} 天", days);
                std::process::exit(1);
            }

            let remaining = (resp.expires_at - now) / 86400;
            println!("[License] 在线验证通过，剩余 {} 天", remaining);

            // write_all_replicas 先于 set_expiry_time（顺序由 main.rs 保证）
            storage::write_all_replicas(
                &hkey,
                &salt,
                resp.activation_ts as u64,
                resp.expires_at as u64,
            );

            time_guard::set_expiry_time(resp.expires_at);
        }

        Err(ref e) => {
            // ── 不可恢复错误：直接退出 ──────────────────────────────────

            // [BUG-13 FIX] 以下错误码不降级离线，直接退出
            if e == network::ERR_NOT_ACTIVATED {
                eprintln!("[License] 密钥尚未激活，请先激活密钥");
                std::process::exit(1);
            }
            if e == network::ERR_REVOKED {
                eprintln!("[License] 授权已被吊销");
                std::process::exit(1);
            }
            if e == network::ERR_INVALID_KEY {
                eprintln!("[License] 无效授权密钥");
                std::process::exit(1);
            }
            if e == network::ERR_EXPIRED {
                eprintln!("[License] 授权已过期（服务端确认）");
                std::process::exit(1);
            }
            if e.starts_with("ERR-FORBIDDEN:") {
                eprintln!("[License] 区域不允许: {e}");
                std::process::exit(1);
            }
            if e.starts_with("ERR-CLOCK-SKEW-PERSISTENT:") {
                eprintln!("[License] 系统时钟异常，请校准后重试");
                std::process::exit(1);
            }

            // ── 网络故障 / 临时错误：尝试离线缓存 ────────────────────────
            eprintln!("[License] 在线验证失败 ({e}), 尝试本地缓存...");

            match storage::read_local_record(&hkey, &salt) {
                storage::LocalReadResult::Insufficient { read_count } => {
                    eprintln!("[License] 本地副本不足 ({}/3)，无法离线验证", read_count);
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
                        eprintln!("[License] 部分副本修复失败（继续使用有效副本）");
                    }

                    // [C-01 FIX + BUG-01 FIX] 离线路径零值检查
                    if local_ts == 0 || local_expires == 0 {
                        eprintln!("[License] 本地记录无效（零值）");
                        std::process::exit(1);
                    }

                    if now >= local_expires as i64 {
                        let days = (now - local_expires as i64) / 86400;
                        eprintln!("[License] 授权已过期 {} 天（离线）", days);
                        std::process::exit(1);
                    }

                    if local_ts as i64 > now + 300 {
                        eprintln!("[License] 本地 activation_ts 在未来（可能被篡改）");
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
