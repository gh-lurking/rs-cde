// client/src/license_guard.rs — 优化版 v3
//
// [C-01 FIX]  activation_ts / expires_at 均需严格正数校验（含零值）
// [BUG-01 FIX] 零值在校验路径中提前拒绝
// [BUG-13 FIX] ERR_NOT_ACTIVATED / ERR_REVOKED / ERR_INVALID_KEY / ERR_EXPIRED 区分处理
// [BUG-14 FIX] 离线路径 expires_at 零值保护，避免 time_guard 接收无效参数
// [BUG-CRIT-2 FIX] 新增 LocalReadResult::Expired 分支处理
//
// [NEW-CLIENT-1] local_is_definitely_expired()：离线优先过期检查
//   对应 CLAUDE.md §4「Goal-Driven Execution」：
//   网络故障时如果本地副本已明确过期，直接退出不等网络超时。
//   注意：此函数仅检查"确定过期"（本地副本 quorum 一致且已过期），
//   如果本地副本不一致或不足，返回 false 放行到联网验证。
//
// [NEW-CLIENT-2] check_expiration_warning()：提前预警即将过期
//   对应 CLAUDE.md §2「Simplicity First」：
//   最小实现：检查 expiry 距离 now 的天数，<= warn_days 时打印警告。
//   EXPIRATION_WARN_DAYS 环境变量控制，默认 7 天。

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
//
// 在联网之前调用。仅当本地存在 quorum 一致且已过期的副本时返回 true。
// 这样在"网络故障 + 本地明确过期"场景下可以立即退出，
// 而不是等待网络超时（10s+）后才回溯本地副本。
//
// 与 CLAUDE.md §1「Think Before Coding」一致的防御性设计：
// - 本地副本不足 2 个 → 返回 false（不确定是否过期，需要联网）
// - 本地副本 quorum 一致但未过期 → 返回 false（需要联网获取最新状态）
// - 本地副本 quorum 一致且已过期 → 返回 true（确定过期）
// - 本地副本不一致（投票失败）→ 返回 false（不确定，需要联网）
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
            // 零值视为无效
            if local_ts == 0 || local_expires == 0 {
                return false;
            }
            // 已过期即返回 true
            now >= local_expires as i64
        }
        storage::LocalReadResult::Expired { .. } => {
            // storage 层已判断过期，直接返回 true
            true
        }
        // 其他情况（副本不足、篡改）→ 不确定，不阻止联网
        _ => false,
    }
}

// ── [NEW-CLIENT-2] 过期预警 ──
//
// 在 check_and_enforce() 成功后调用，检查许可证距离过期还有多少天。
// 如果剩余天数 <= warn_days，打印彩色警告到 stderr，但不阻止运行。
// 与 CLAUDE.md §4「Goal-Driven Execution」一致：非阻塞信息提示。
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
        return; // 不应在此处到达，check_and_enforce 已拦截
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
                eprintln!("[License] key expired");
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
