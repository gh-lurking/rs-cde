// client/src/license_guard.rs — 优化版 v2
//
// [C-01 FIX]  activation_ts / expires_at 均需严格正数校验（含零值）
// [BUG-01 FIX] 零值在校验路径中提前拒绝
// [BUG-13 FIX] ERR_NOT_ACTIVATED / ERR_REVOKED / ERR_INVALID_KEY / ERR_EXPIRED 区分处理
// [BUG-14 FIX] 离线路径 expires_at 零值保护，避免 time_guard 接收无效参数
//
// [BUG-CRIT-2 FIX] 新增 LocalReadResult::Expired 分支处理
//   对应 CLAUDE.md §1 「Think Before Coding」：
//   原代码只有 Success/Tampered/Insufficient 分支，
//   现在 storage.rs 返回 Expired 变体时能给出准确的 "key expired (local)" 提示

use crate::{network, storage, time_guard};
use obfstr::obfstr;
use std::time::{SystemTime, UNIX_EPOCH};

pub async fn check_and_enforce() {
    let hkey = std::env::var("HKEY").unwrap_or_else(|_| {
        eprintln!("[License] missing HKEY env");
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
                eprintln!("[License] key revoked");
                std::process::exit(1);
            }
            if resp.activation_ts <= 0 || resp.expires_at <= 0 {
                eprintln!("[License] invalid server timestamps");
                std::process::exit(1);
            }
            if resp.activation_ts > now + 300 {
                eprintln!("[License] activation_ts is in the future");
                std::process::exit(1);
            }
            if resp.activation_ts >= resp.expires_at {
                eprintln!("[License] inconsistent timestamps");
                std::process::exit(1);
            }
            if now >= resp.expires_at {
                eprintln!("[License] key expired");
                std::process::exit(1);
            }

            storage::write_all_replicas(
                &hkey,
                &salt,
                resp.activation_ts as u64,
                resp.expires_at as u64,
            );
            time_guard::set_expiry_time(resp.expires_at);
        }
        Err(ref e) => {
            if e == network::ERR_NOT_ACTIVATED {
                eprintln!("[License] key not activated");
                std::process::exit(1);
            }
            if e == network::ERR_REVOKED {
                eprintln!("[License] key revoked");
                std::process::exit(1);
            }
            if e == network::ERR_INVALID_KEY {
                eprintln!("[License] invalid key");
                std::process::exit(1);
            }
            if e == network::ERR_EXPIRED {
                eprintln!("[License] key expired");
                std::process::exit(1);
            }
            if e.starts_with("ERR-CLOCK-SKEW-PERSISTENT:") {
                eprintln!("[License] local clock skew too large");
                std::process::exit(1);
            }

            match storage::read_local_record(&hkey, &salt) {
                storage::LocalReadResult::Insufficient { read_count } => {
                    eprintln!("[License] local replicas insufficient ({}/3)", read_count);
                    std::process::exit(1);
                }
                storage::LocalReadResult::Tampered { read_count } => {
                    eprintln!("[License] local replicas tampered ({}/3)", read_count);
                    std::process::exit(1);
                }
                // [BUG-CRIT-2 FIX] 新增 Expired 分支
                // 离线场景下本地副本已过期，给出准确的过期提示
                storage::LocalReadResult::Expired {
                    value: (_, _local_expires),
                    read_count: _,
                } => {
                    eprintln!("[License] key expired (local)");
                    // 不设置 time_guard，因为已过期，直接退出
                    std::process::exit(1);
                }
                storage::LocalReadResult::Success {
                    value: (local_ts, local_expires),
                    read_count: _,
                    repair_failed: _,
                } => {
                    if local_ts == 0 || local_expires == 0 {
                        eprintln!("[License] invalid local timestamps");
                        std::process::exit(1);
                    }
                    if now >= local_expires as i64 {
                        eprintln!("[License] key expired (local)");
                        std::process::exit(1);
                    }
                    time_guard::set_expiry_time(local_expires as i64);
                }
            }
        }
    }
}
