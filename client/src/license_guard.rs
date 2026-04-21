// client/src/license_guard.rs — 优化版 v2
// ✅ C-01 FIX: 离线模式先做零值检查，再做过期检查（顺序正确）
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
        // ─── 在线成功路径 ──────────────────────────────────────
        Ok(resp) => {
            if resp.revoked {
                eprintln!("[License] Server returned revoked=true");
                std::process::exit(1);
            }
            if resp.activation_ts <= 0 || resp.expires_at <= 0 {
                eprintln!("[License] Invalid record from server");
                std::process::exit(1);
            }
            if resp.activation_ts > now + 300 {
                eprintln!("[License] activation_ts in the future, clock tampering?");
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
            println!("[License] Online OK, {} days remaining", remaining);

            storage::write_all_replicas(
                &hkey,
                &salt,
                resp.activation_ts as u64,
                resp.expires_at as u64,
            );
            time_guard::set_expiry_time(resp.expires_at);
        }

        // ─── 网络失败路径 ──────────────────────────────────────
        Err(ref e) => {
            if e == network::ERR_REVOKED {
                eprintln!("[License] Key revoked");
                std::process::exit(1);
            }
            if e == network::ERR_INVALID_KEY {
                eprintln!("[License] Invalid key");
                std::process::exit(1);
            }
            if e == network::ERR_NOT_ACTIVATED {
                eprintln!("[License] Key not activated");
                std::process::exit(1);
            }
            if e == network::ERR_EXPIRED {
                eprintln!("[License] Key expired (server)");
                std::process::exit(1);
            }
            if e.starts_with("ERR-FORBIDDEN:") {
                eprintln!("[License] Region restricted");
                std::process::exit(1);
            }
            if e.starts_with("ERR-CLOCK-SKEW-PERSISTENT:") {
                eprintln!("[License] Persistent clock skew");
                std::process::exit(1);
            }

            eprintln!("[License] Online failed ({}), trying local cache...", e);

            match storage::read_local_record(&hkey, &salt) {
                storage::LocalReadResult::Insufficient { read_count } => {
                    eprintln!("[License] Insufficient replicas ({}/3)", read_count);
                    std::process::exit(1);
                }
                storage::LocalReadResult::Tampered { read_count } => {
                    eprintln!("[License] Replicas tampered ({}/3)", read_count);
                    std::process::exit(1);
                }
                storage::LocalReadResult::Success {
                    value: (local_ts, local_expires),
                    read_count: _,
                    repair_failed,
                } => {
                    if repair_failed {
                        eprintln!("[License] Replica repair failed, caution");
                    }

                    // ✅ C-01 FIX 步骤 1：先做零值检查
                    if local_ts == 0 || local_expires == 0 {
                        eprintln!("[License] Corrupt local record (zero values)");
                        std::process::exit(1);
                    }

                    // ✅ C-01 FIX 步骤 2：再做过期检查
                    if now >= local_expires as i64 {
                        let days = (now - local_expires as i64) / 86400;
                        eprintln!("[License] Key expired {} days ago (offline)", days);
                        std::process::exit(1);
                    }

                    if local_ts as i64 > now + 300 {
                        eprintln!("[License] activation_ts in future (tamper?)");
                        std::process::exit(1);
                    }
                    if local_ts >= local_expires {
                        eprintln!("[License] Corrupt local record (ts >= exp)");
                        std::process::exit(1);
                    }

                    let remaining = (local_expires as i64 - now) / 86400;
                    println!("[License] Offline OK, {} days remaining", remaining);
                    time_guard::set_expiry_time(local_expires as i64);
                }
            }
        }
    }
}
