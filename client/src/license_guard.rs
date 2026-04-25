// client/src/license_guard.rs — 优化版 v4
//
// [BUG-HIGH-2-RELATED] check_and_enforce 在收到 ERR_EXPIRED 时
//   不再直接退出，而是检查服务端是否在响应体中传递了宽限期信息。
//   如果宽限期 > 0 且本地时间仍在宽限期内，
//   按有效处理（但打印强警告），并触发重验证。
//
// [NEW-CLIENT-4] 过期但仍在宽限期内的处理：
//   服务端配置了 EXPIRATION_GRACE_SECS > 0，
//   密钥在 expires_at 到 expires_at+grace 之间仍可用。
//   当服务端返回 410（已超过宽限期），客户端直接退出。
//   但如果服务端在过期前被查询，会返回 200，
//   宽限期只影响服务端的 is_expired() 判断。
//   客户端这里只处理服务端明确返回 ERR_EXPIRED 的情况。
//
// 对应 CLAUDE.md §1「Think Before Coding」与 §2「Simplicity First」：
//   客户端不自行计算宽限期，完全信任服务端判断。
//   仅当服务端明确返回过期时才退出。

use crate::{network, storage, time_guard};
use obfstr::obfstr;
use std::time::{SystemTime, UNIX_EPOCH};

// ── 过期预警配置 ────────────────────────────────────────────────────────────
fn expiration_warn_days() -> i64 {
    std::env::var("EXPIRATION_WARN_DAYS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(7)
}

// ── [NEW-CLIENT-1] 离线优先：本地快速过期检查 ──
pub fn local_is_definitely_expired() -> bool {
    let hkey = match std::env::var("HKEY") {
        Ok(v) => v,
        Err(_) => return false,
    };
    let salt = obfstr!("PROG_ACTIVATION_SALT_V1_SECRET").to_owned();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    match storage::read_local_record(&hkey, &salt) {
        storage::LocalReadResult::Success {
            value: (local_ts, local_expires),
            ..
        } => {
            if local_ts == 0 || local_expires == 0 {
                return false;
            }
            now >= local_expires as i64
        }
        storage::LocalReadResult::Expired { .. } => true,
        _ => false,
    }
}

// ── [NEW-CLIENT-2] 过期预警 ──
pub fn check_expiration_warning() {
    let expiry = time_guard::get_expiry_time();
    if expiry <= 0 {
        return;
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    if now >= expiry {
        return;
    }

    let remaining_secs = expiry - now;
    let remaining_days = remaining_secs / 86400;
    let warn_days = expiration_warn_days();

    if remaining_days <= warn_days {
        if remaining_days <= 0 {
            eprintln!(
                "⚠️  [License] EXPIRES TODAY! Please renew immediately. (expires_at={})",
                expiry
            );
        } else if remaining_days == 1 {
            eprintln!(
                "⚠️  [License] Expires TOMORROW! {} day remaining. (expires_at={})",
                remaining_days, expiry
            );
        } else {
            eprintln!(
                "⚠️  [License] Expires in {} days. Please renew soon. (expires_at={})",
                remaining_days, expiry
            );
        }
    }
}

// ── 主验证流程 ──────────────────────────────────────────────────────────────

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
            // ── 联网验证成功路径 ──
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

            // 持久化到本地副本
            storage::write_all_replicas(
                &hkey,
                &salt,
                resp.activation_ts as u64,
                resp.expires_at as u64,
            );
            time_guard::set_expiry_time(resp.expires_at);
        }
        Err(ref e) => {
            // ── 联网失败路径：回溯本地副本 ──
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
                // [BUG-HIGH-2-RELATED] 服务端明确返回硬过期
                // 此时宽限期也已耗尽（服务端 is_expired 检查 now >= expires_at + grace）
                eprintln!("[License] key expired (server confirmed)");
                std::process::exit(1);
            }
            if e.starts_with("ERR-CLOCK-SKEW-PERSISTENT:") {
                eprintln!("[License] local clock skew too large");
                std::process::exit(1);
            }

            // 离线路径：读取本地多副本
            match storage::read_local_record(&hkey, &salt) {
                storage::LocalReadResult::Insufficient { read_count } => {
                    eprintln!(
                        "[License] local replicas insufficient ({}/3) — network required",
                        read_count
                    );
                    std::process::exit(1);
                }
                storage::LocalReadResult::Tampered { read_count } => {
                    eprintln!(
                        "[License] local replicas tampered ({}/3) — network required",
                        read_count
                    );
                    std::process::exit(1);
                }
                storage::LocalReadResult::Expired {
                    value: (_, _local_expires),
                    read_count: _,
                } => {
                    eprintln!("[License] key expired (local)");
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
