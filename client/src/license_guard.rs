// client/src/license_guard.rs — 优化版 v8
// ✅ MINOR-C FIX: 本地缓存 Success 分支校验顺序修正
//   ① 先检查 local_ts==0||local_expires==0（数据有效性）
//   ② 再检查 now < local_ts_i64（时钟异常）
//   ③ 最后做过期检查
// ✅ 原有所有 MAJOR-1 / CRIT-3 / revoked=true 防御性检查保留

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
            // [1] 防御：revoked=true 不应出现在 200 响应中
            if resp.revoked {
                eprintln!(
                    "[License] Server returned revoked=true with HTTP 200, data anomaly, aborting"
                );
                std::process::exit(1);
            }

            // [2] activation_ts > 0 && expires_at > 0
            if resp.activation_ts <= 0 || resp.expires_at <= 0 {
                eprintln!(
                    "[License] Invalid record (activation_ts={}, expires_at={}), data corrupted, aborting",
                    resp.activation_ts, resp.expires_at
                );
                std::process::exit(1);
            }

            // [3] activation_ts 不能在未来（允许 5 分钟时钟偏差）
            if resp.activation_ts > now + 300 {
                eprintln!(
                    "[License] activation_ts({}) is in the future (now={}), possible clock tampering, aborting",
                    resp.activation_ts, now
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

            // [5] 写入本地缓存（数据合法才写入）
            storage::write_all_replicas(
                &hkey,
                &salt,
                resp.activation_ts as u64,
                resp.expires_at as u64,
            );
        }

        Err(ref e) => {
            // ── 已知错误码：直接拒绝，不走本地缓存 ──────────────────────
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

            // ── 网络故障 → 降级到本地缓存 ────────────────────────────────
            eprintln!(
                "[License] Online verification failed ({}), trying local cache...",
                e
            );

            let local_result = storage::read_local_record(&hkey, &salt);
            match local_result {
                storage::LocalReadResult::Insufficient { read_count: count } => {
                    eprintln!(
                        "[License] Insufficient local replicas ({}/3), cannot verify offline, aborting",
                        count
                    );
                    std::process::exit(1);
                }

                storage::LocalReadResult::Tampered { read_count: count } => {
                    eprintln!(
                        "[License] Local replicas tampered ({}/3 inconsistent), aborting",
                        count
                    );
                    std::process::exit(1);
                }

                storage::LocalReadResult::Success {
                    value: (local_ts, local_expires),
                    read_count: _,
                } => {
                    // ✅ MINOR-C FIX: 校验顺序修正
                    // ① 先检查数据有效性（0 值表示数据损坏）
                    if local_ts == 0 || local_expires == 0 {
                        eprintln!(
                            "[License] Local cache data invalid (activation_ts={}, expires_at={}), aborting",
                            local_ts, local_expires
                        );
                        std::process::exit(1);
                    }

                    let local_ts_i64 = local_ts as i64;
                    let local_expires_i64 = local_expires as i64;
                    // ② 检查时钟异常（activation_ts 不能在未来）
                    if now < local_ts_i64 {
                        eprintln!(
                            "[License] Local cache activation_ts is in the future (now={}, activation_ts={}), clock anomaly, aborting",
                            now, local_ts_i64
                        );
                        std::process::exit(1);
                    }

                    // ③ 过期检查
                    if now >= local_expires_i64 {
                        let days = (now - local_expires_i64) / 86400;
                        eprintln!(
                            "[License] Local cache: key expired {} days ago (expires={}, now={}), please connect to renew",
                            days, local_expires_i64, now
                        );

                        std::process::exit(1);
                    }

                    let remaining = (local_expires_i64 - now) / 86400;
                    println!(
                        "[License] ✅ Offline verification passed (local cache), ~{} days remaining (please sync online soon)",
                        remaining
                    );
                }
            }
        }
    }
}
