// client/src/license_guard.rs — 最终优化版
// ✅ CRITICAL FIX: 离线模式必须校验 local_expires vs now
// ✅ NEW: 集成时间监控

use crate::{network, storage, time_guard};
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
            if resp.revoked {
                eprintln!("[License] Server returned revoked=true");
                std::process::exit(1);
            }
            if resp.activation_ts <= 0 || resp.expires_at <= 0 {
                eprintln!("[License] Invalid record");
                std::process::exit(1);
            }
            if resp.activation_ts > now + 300 {
                eprintln!("[License] activation_ts in the future, clock tampering");
                std::process::exit(1);
            }
            if resp.activation_ts >= resp.expires_at {
                eprintln!("[License] Data anomaly: activation_ts >= expires_at");
                std::process::exit(1);
            }
            if now >= resp.expires_at {
                let days = (now - resp.expires_at) / 86400;
                eprintln!("[License] Key expired {} days ago", days);
                std::process::exit(1);
            }

            let remaining = (resp.expires_at - now) / 86400;
            println!(
                "[License] Online verification passed, {} days remaining",
                remaining
            );

            // 写入本地缓存
            storage::write_all_replicas(
                &hkey,
                &salt,
                resp.activation_ts as u64,
                resp.expires_at as u64,
            );

            // ✅ NEW: 设置时间监控基准
            time_guard::set_expiry_time(resp.expires_at);
        }

        Err(ref e) => {
            // 确定性失败：直接退出
            if e == network::ERR_REVOKED {
                eprintln!("[License] Key revoked by server");
                std::process::exit(1);
            }
            if e == network::ERR_INVALID_KEY {
                eprintln!("[License] Invalid license key");
                std::process::exit(1);
            }
            if e == network::ERR_NOT_ACTIVATED {
                eprintln!("[License] License key not yet activated");
                std::process::exit(1);
            }
            if e == network::ERR_EXPIRED {
                eprintln!("[License] Key expired");
                std::process::exit(1);
            }
            if e.starts_with("ERR-FORBIDDEN:") {
                eprintln!("[License] Key restricted by region");
                std::process::exit(1);
            }
            if e.starts_with("ERR-CLOCK-SKEW-PERSISTENT:") {
                eprintln!("[License] Persistent clock skew detected");
                std::process::exit(1);
            }

            eprintln!("[License] Online verification failed, trying local cache...");

            let local_result = storage::read_local_record(&hkey, &salt);
            match local_result {
                storage::LocalReadResult::Insufficient { read_count } => {
                    eprintln!("[License] Insufficient local replicas ({}/3)", read_count);
                    std::process::exit(1);
                }

                storage::LocalReadResult::Tampered { read_count } => {
                    eprintln!("[License] Local replicas tampered ({}/3)", read_count);
                    std::process::exit(1);
                }

                storage::LocalReadResult::Success {
                    value: (local_ts, local_expires),
                    read_count: _,
                    repair_failed,
                } => {
                    if repair_failed {
                        eprintln!("[License] Local replica repair failed, proceeding with caution");
                    }

                    // ✅ CRITICAL: 离线模式首先检查过期时间
                    if now >= local_expires as i64 {
                        let days = (now - local_expires as i64) / 86400;
                        eprintln!("[License] Key expired {} days ago (offline cache)", days);
                        std::process::exit(1);
                    }

                    if local_ts == 0 || local_expires == 0 {
                        eprintln!("[License] Corrupt local record");
                        std::process::exit(1);
                    }

                    if local_ts as i64 > now + 300 {
                        eprintln!("[License] Local record activation_ts in future");
                        std::process::exit(1);
                    }

                    if local_ts >= local_expires {
                        eprintln!("[License] Corrupt local record");
                        std::process::exit(1);
                    }

                    let remaining = (local_expires as i64 - now) / 86400;
                    println!(
                        "[License] Offline verification passed, {} days remaining",
                        remaining
                    );

                    // ✅ NEW: 设置时间监控基准
                    time_guard::set_expiry_time(local_expires as i64);
                }
            }
        }
    }
}
