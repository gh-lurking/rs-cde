// client/src/license_guard.rs — 优化版 v5
//
// ✅ OPT-MINOR-3: 移除 Ok(resp) 分支中的冗余双重条件检查（dead code 消除）
// ✅ 保留所有原有修复（FIX CRIT-1/MAJOR-1/CRIT-3）
// ✅ 新增：写缓存前卫语句仅保留一次，逻辑更清晰

use crate::{network, storage};
use obfstr::obfstr;
use std::time::{SystemTime, UNIX_EPOCH};

pub async fn check_and_enforce() {
    let hkey = std::env::var("HKEY").unwrap_or_else(|_| {
        eprintln!("[License] No HKEY provided");
        std::process::exit(1);
    });

    let salt = obfstr!("PROG_ACTIVATION_SALT_V1_SECRET").to_owned();
    let server_url = obfstr!("http://localhost:8080").to_owned();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    match network::verify_online(&hkey, &server_url).await {
        Ok(resp) => {
            // 服务端 verify() 在 revoked/not-activated/expired 时返回非 2xx，
            // 所以 Ok(resp) 只有「正常已激活未过期」状态。
            // ✅ OPT-MINOR-3: 只做一次检查，移除冗余的写缓存前二次检查

            // 未激活（activation_ts=0 先于 expires_at，防 expires_at=0 误报）
            if resp.activation_ts == 0 {
                eprintln!("[License] Key 尚未激活，请先完成激活");
                std::process::exit(1);
            }

            // 已过期（activation_ts>0 时 expires_at 才有意义）
            if now >= resp.expires_at {
                let days = (now - resp.expires_at) / 86400;
                eprintln!("[License] 许可证已过期 {} 天，请联系支持", days);
                std::process::exit(1);
            }

            // 服务端在 revoked=true 时返回 403+ERR-REVOKED → Err(ERR-REVOKED) → exit(1)
            // Ok 分支到达这里时 revoked 必然为 false（服务端保证），无需检查

            let remaining = (resp.expires_at - now) / 86400;
            println!("[License] ✅ 在线校验通过，剩余 {} 天", remaining);

            // ✅ OPT-MINOR-3: 直接写入（前置检查已保证状态合法，移除重复的 if 条件）
            storage::write_all_replicas(
                &hkey,
                &salt,
                resp.activation_ts as u64,
                resp.expires_at as u64,
            );
        }

        Err(ref e) => {
            // ── 业务明确拒绝 → 立即退出，不走离线缓存 ──────────────────────

            if e == network::ERR_REVOKED {
                eprintln!("[License] 许可证已被吊销（服务端确认），立即退出");
                std::process::exit(1);
            }
            if e == network::ERR_INVALID_KEY {
                eprintln!("[License] 无效的 License Key（服务端确认），立即退出");
                std::process::exit(1);
            }
            if e == network::ERR_NOT_ACTIVATED {
                eprintln!("[License] License Key 尚未激活（服务端确认），立即退出");
                std::process::exit(1);
            }
            if e == network::ERR_EXPIRED {
                eprintln!("[License] 许可证已过期（服务端确认），立即退出");
                std::process::exit(1);
            }
            // ERR-FORBIDDEN:* 通用业务拒绝
            if e.starts_with("ERR-FORBIDDEN:") {
                eprintln!("[License] 服务端业务拒绝 ({})，立即退出", e);
                std::process::exit(1);
            }

            // ── 真正的网络错误 → 降级到本地缓存 ────────────────────────────
            eprintln!("[License] 在线校验失败（{}），使用本地缓存校验", e);

            let local_result = storage::read_local_record(&hkey, &salt);

            match local_result {
                storage::LocalReadResult::Insufficient { read_count: count } => {
                    eprintln!(
                        "[License] 本地副本不足（{}/3），可能首次运行未缓存或文件丢失，退出",
                        count
                    );
                    std::process::exit(1);
                }
                storage::LocalReadResult::Tampered { read_count: count } => {
                    eprintln!(
                        "[License] 检测到本地副本篡改（{}/3副本不一致），退出",
                        count
                    );
                    std::process::exit(1);
                }
                storage::LocalReadResult::Success {
                    value: (local_ts, local_expires),
                    read_count: _,
                } => {
                    let local_ts_i64 = local_ts as i64;
                    let local_expires_i64 = local_expires as i64;

                    // 时钟回拨检测
                    if now < local_ts_i64 {
                        eprintln!(
                            "[License] 检测到时钟回拨（当前={}, 激活时间={}），退出",
                            now, local_ts_i64
                        );
                        std::process::exit(1);
                    }

                    // 本地过期检查
                    if now >= local_expires_i64 {
                        let days = (now - local_expires_i64) / 86400;
                        eprintln!("[License] 许可证已过期 {} 天（本地缓存），退出", days);
                        std::process::exit(1);
                    }

                    let remaining = (local_expires_i64 - now) / 86400;
                    println!(
                        "[License] ✅ 本地缓存校验通过（离线模式），剩余约 {} 天",
                        remaining
                    );
                }
            }
        }
    }
}
