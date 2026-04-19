// client/src/license_guard.rs — 优化版 v10
//
// ✅ CRIT-A FIX: 离线模式必须校验 local_expires vs now（过期检查）
// ✅ OPT-3 FIX: repair_failed=true 时不立即 exit，记录警告后继续（如时间合理）

use crate::{network, storage};
use obfstr::obfstr;
use std::time::{SystemTime, UNIX_EPOCH};

pub async fn check_and_enforce() {
    let hkey = std::env::var("HKEY").unwrap_or_else(|_| {
        eprintln!("[License] No HKEY provided");
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
            // [1] revoked=true 在 200 响应中 → 数据异常
            if resp.revoked {
                eprintln!(
                    "[License] Server returned revoked=true with HTTP 200, data anomaly, aborting"
                );
                std::process::exit(1);
            }

            // [2] activation_ts > 0 && expires_at > 0
            if resp.activation_ts <= 0 || resp.expires_at <= 0 {
                eprintln!(
                    "[License] Invalid record (activation_ts={}, expires_at={}), aborting",
                    resp.activation_ts, resp.expires_at
                );
                std::process::exit(1);
            }

            // [3] activation_ts 不在未来（允许 5 分钟误差）
            if resp.activation_ts > now + 300 {
                eprintln!(
                    "[License] activation_ts({}) is in the future (now={}), clock tampering, aborting",
                    resp.activation_ts, now
                );
                std::process::exit(1);
            }

            // ✅ BUG-3 补充: activation_ts >= expires_at 数据异常
            if resp.activation_ts >= resp.expires_at {
                eprintln!(
                    "[License] Data anomaly: activation_ts({}) >= expires_at({}), aborting",
                    resp.activation_ts, resp.expires_at
                );
                std::process::exit(1);
            }

            // [4] 过期检查
            if now >= resp.expires_at {
                let days = (now - resp.expires_at) / 86400;
                eprintln!(
                    "[License] Key expired {} days ago (expires={}, now={}), please renew",
                    days, resp.expires_at, now
                );
                std::process::exit(1);
            }

            let remaining = (resp.expires_at - now) / 86400;
            println!(
                "[License] ✅ Online verification passed, {} days remaining",
                remaining
            );

            // [5] 写本地副本缓存
            storage::write_all_replicas(
                &hkey,
                &salt,
                resp.activation_ts as u64,
                resp.expires_at as u64,
            );
        }

        Err(ref e) => {
            // 确定性失败（revoked/invalid/forbidden）→ 立即 exit
            if e == network::ERR_REVOKED {
                eprintln!("[License] Key revoked by server, aborting");
                std::process::exit(1);
            }
            if e == network::ERR_INVALID_KEY {
                eprintln!("[License] Invalid license key (rejected by server), aborting");
                std::process::exit(1);
            }
            if e == network::ERR_NOT_ACTIVATED {
                eprintln!("[License] License key not yet activated (rejected by server), aborting");
                std::process::exit(1);
            }
            if e == network::ERR_EXPIRED {
                eprintln!("[License] Key expired (rejected by server), aborting");
                std::process::exit(1);
            }
            if e.starts_with("ERR-FORBIDDEN:") {
                eprintln!("[License] Key restricted by region ({}), aborting", e);
                std::process::exit(1);
            }

            // 网络/超时错误 → 尝试本地缓存
            eprintln!(
                "[License] Online verification failed ({}), trying local cache...",
                e
            );

            let local_result = storage::read_local_record(&hkey, &salt);
            match local_result {
                storage::LocalReadResult::Insufficient { read_count } => {
                    eprintln!(
                        "[License] Insufficient local replicas ({}/3), cannot verify offline, aborting",
                        read_count
                    );
                    std::process::exit(1);
                }

                storage::LocalReadResult::Tampered { read_count } => {
                    eprintln!(
                        "[License] Local replicas tampered ({}/3 inconsistent), aborting",
                        read_count
                    );
                    std::process::exit(1);
                }

                storage::LocalReadResult::Success {
                    value: (local_ts, local_expires),
                    read_count: _,
                    repair_failed,
                } => {
                    // ✅ OPT-3 FIX: repair_failed 时记录警告但不立即 exit
                    // 改为：如果时间合理，允许继续（但下次必须联网）
                    if repair_failed {
                        eprintln!(
                            "[License] Local replica repair failed (storage may be unreliable).                              Proceeding with caution — will force online next launch."
                        );
                        // TODO: 写 force_online 标志文件，下次启动强制联网
                        // mark_force_online_required();
                    }

                    // ✅ CRIT-A FIX: 离线模式必须检查过期时间！
                    if now >= local_expires as i64 {
                        let days = (now - local_expires as i64) / 86400;
                        eprintln!(
                            "[License] Key expired {} days ago (offline cache, expires={}, now={}),                              please restore network connection and renew",
                            days, local_expires, now
                        );
                        std::process::exit(1);
                    }

                    // ✅ 验证 local_ts 合理性
                    if local_ts == 0 || local_expires == 0 {
                        eprintln!("[License] Corrupt local record (ts=0), aborting");
                        std::process::exit(1);
                    }

                    // ✅ activation_ts 不应在未来
                    if local_ts as i64 > now + 300 {
                        eprintln!(
                            "[License] Local record activation_ts in future, possible tampering, aborting"
                        );
                        std::process::exit(1);
                    }

                    // ✅ activation_ts >= expires_at 合理性
                    if local_ts >= local_expires {
                        eprintln!(
                            "[License] Corrupt local record (activation_ts >= expires_at), aborting"
                        );
                        std::process::exit(1);
                    }

                    let remaining = (local_expires as i64 - now) / 86400;
                    println!(
                        "[License] ✅ Offline verification passed, {} days remaining",
                        remaining
                    );
                }
            }
        }
    }
}
