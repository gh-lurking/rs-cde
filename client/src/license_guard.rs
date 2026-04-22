// client/src/license_guard.rs
//
// [C-01 FIX]  activation_ts / expires_at 均需严格正数校验（含零值）
// [BUG-01 FIX] 零值在校验路径中提前拒绝
// [BUG-13 FIX] ERR_NOT_ACTIVATED / ERR_REVOKED / ERR_INVALID_KEY / ERR_EXPIRED 区分处理
// [BUG-14 FIX] 离线路径 expires_at 零值保护，避免 time_guard 接收无效参数

use crate::{network, storage, time_guard};
use obfstr::obfstr;
use std::time::{SystemTime, UNIX_EPOCH};

pub async fn check_and_enforce() {
    let hkey = std::env::var("HKEY").unwrap_or_else(|_| {
        eprintln!("[License] 未检测到 HKEY 环境变量，请配置后启动");
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
            // ──────────────── 在线校验成功路径 ──────────────────────────

            if resp.revoked {
                eprintln!("[License] 密钥已被撤销");
                std::process::exit(1);
            }

            // [C-01 FIX + BUG-14 FIX] 零值保护：服务端 BUG-V4 修复后此处为冗余保障
            if resp.activation_ts <= 0 || resp.expires_at <= 0 {
                eprintln!("[License] 服务端返回无效激活数据（零值），请联系运维");
                std::process::exit(1);
            }

            // 时间戳合理性：activation_ts 不应超过 now+300s（允许 5 分钟时钟偏差）
            if resp.activation_ts > now + 300 {
                eprintln!("[License] activation_ts 在未来，可能存在时钟偏差");
                std::process::exit(1);
            }

            // 逻辑一致性
            if resp.activation_ts >= resp.expires_at {
                eprintln!("[License] 数据异常：activation_ts >= expires_at");
                std::process::exit(1);
            }

            // 过期检查
            if now >= resp.expires_at {
                let days = (now - resp.expires_at) / 86400;
                eprintln!("[License] 密钥已过期 {} 天", days);
                std::process::exit(1);
            }

            let remaining = (resp.expires_at - now) / 86400;
            println!("[License] 在线校验通过，剩余 {} 天", remaining);

            // 写本地副本 & 设置 time_guard 到期时间
            // write_all_replicas 由 main.rs 中 set_expiry_time 调用（见注释）
            storage::write_all_replicas(
                &hkey,
                &salt,
                resp.activation_ts as u64,
                resp.expires_at as u64,
            );
            // [BUG-14 FIX] set_expiry_time 在 start_monitor 之前调用
            time_guard::set_expiry_time(resp.expires_at);
        }

        Err(ref e) => {
            // ──────────────── 网络/服务器错误路径 ──────────────────────

            // [BUG-13 FIX] 明确区分各类错误码，不同错误给出不同提示

            if e == network::ERR_NOT_ACTIVATED {
                eprintln!("[License] 密钥尚未激活，请先激活");
                std::process::exit(1);
            }
            if e == network::ERR_REVOKED {
                eprintln!("[License] 密钥已被撤销");
                std::process::exit(1);
            }
            if e == network::ERR_INVALID_KEY {
                eprintln!("[License] 无效密钥");
                std::process::exit(1);
            }
            if e == network::ERR_EXPIRED {
                eprintln!("[License] 密钥已过期（服务端判定）");
                std::process::exit(1);
            }
            if e.starts_with("ERR-FORBIDDEN:") {
                eprintln!("[License] 权限不足，无法验证: {e}");
                std::process::exit(1);
            }
            if e.starts_with("ERR-CLOCK-SKEW-PERSISTENT:") {
                eprintln!("[License] 本机时钟偏差持续过大，请同步时间");
                std::process::exit(1);
            }

            // ── 网络超时 / 服务不可用：降级到本地缓存 ──────────────────
            eprintln!("[License] 在线校验失败 ({e})，尝试本地缓存...");

            match storage::read_local_record(&hkey, &salt) {
                storage::LocalReadResult::Insufficient { read_count } => {
                    eprintln!("[License] 本地副本不足 ({}/3)，无法离线校验", read_count);
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
                        eprintln!("[License] 部分副本修复失败（少数副本可能已损坏）");
                    }

                    // [C-01 FIX + BUG-01 FIX] 本地缓存零值保护
                    if local_ts == 0 || local_expires == 0 {
                        eprintln!("[License] 本地缓存数据无效（零值）");
                        std::process::exit(1);
                    }

                    if now >= local_expires as i64 {
                        let days = (now - local_expires as i64) / 86400;
                        eprintln!("[License] 密钥已过期 {} 天（本地缓存）", days);
                        std::process::exit(1);
                    }

                    let remaining = (local_expires as i64 - now) / 86400;
                    println!("[License] 离线校验通过，剩余 {} 天（本地缓存）", remaining);

                    // [BUG-14 FIX] 离线路径也必须 set_expiry_time
                    time_guard::set_expiry_time(local_expires as i64);
                }
            }
        }
    }
}
