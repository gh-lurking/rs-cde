// client/src/license_guard.rs — 优化版 v6 (Bug修复版)
//
// ✅ MAJOR-1 FIX: Ok(resp) 分支增加 expires_at==0 防御性检查
//   防止服务端返回 200 + expires_at=0（DB异常）时 now>=0 恒真导致所有用户被锁出
// ✅ 保留所有原有修复（CRIT-1/CRIT-3/OPT-MINOR-3）

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
            // Ok(resp) 理论上只有「正常已激活未过期」状态。
            // 但需防御性校验，防止服务端 Bug 或 DB 异常返回无效数据。

            // ✅ MAJOR-1 FIX: 检查 activation_ts 和 expires_at 都必须 > 0
            // 若服务端返回 200 + expires_at=0（DB异常），
            // 原代码的 now >= 0 恒真，会拒绝所有合法用户（DoS）
            if resp.activation_ts == 0 || resp.expires_at == 0 {
                eprintln!(
                    "[License] 服务端返回无效数据(activation_ts={}, expires_at={})，拒绝信任，请联系支持",
                    resp.activation_ts, resp.expires_at
                );
                std::process::exit(1);
            }

            // ✅ MAJOR-1 FIX: 保留过期检查（防客户端时钟超前 > 服务端授权范围的极端情况）
            // 此时 resp.expires_at > 0 已保证，now >= expires_at 不会恒真
            if now >= resp.expires_at {
                let days = (now - resp.expires_at) / 86400;
                eprintln!(
                    "[License] 客户端时钟可能超前 {} 天（服务端授权到期: {}，当前时钟: {}），请检查系统时间",
                    days, resp.expires_at, now
                );
                std::process::exit(1);
            }

            let remaining = (resp.expires_at - now) / 86400;
            println!("[License] ✅ 在线校验通过，剩余 {} 天", remaining);

            // 写入本地缓存（前置检查已保证数据合法）
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
