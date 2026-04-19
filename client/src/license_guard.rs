// client/src/license_guard.rs — 优化版 v7
// ✅ MAJOR-1 FIX: 检查 activation_ts > 0 && expires_at > 0（在 now>=expires_at 之前）
// ✅ 新增: revoked=true 在 200 响应时的防御性检查
// ✅ 新增: activation_ts 不能在未来（防时钟篡改）
// ✅ CRIT-3 客户端: 确保与服务端 expires_at > 0 校验对应，不依赖服务端保证

use crate::{network, storage};
use obfstr::obfstr;
use std::time::{SystemTime, UNIX_EPOCH};

pub async fn check_and_enforce() {
    let hkey = std::env::var("HKEY").unwrap_or_else(|_| {
        eprintln!("[License] No HKEY provided");
        std::process::exit(1);
    });

    let salt = obfstr!("PROG_ACTIVATION_SALT_V1_SECRET").to_owned();
    let server_url = obfstr!("https://license.example.com").to_owned(); // ✅ 生产用 HTTPS

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    match network::verify_online(&hkey, &server_url).await {
        Ok(resp) => {
            // ✅ [1] 防御：revoked=true 不应出现在 200 响应中
            if resp.revoked {
                eprintln!("[License] 服务端返回 revoked=true 但状态码 200，数据异常，退出");
                std::process::exit(1);
            }

            // ✅ [2] MAJOR-1 FIX: 确保 activation_ts > 0 && expires_at > 0
            if resp.activation_ts <= 0 || resp.expires_at <= 0 {
                eprintln!(
                    "[License] 无效记录(activation_ts={}, expires_at={})，数据损坏，拒绝运行",
                    resp.activation_ts, resp.expires_at
                );
                std::process::exit(1);
            }

            // ✅ [3] activation_ts 不能在未来（允许 5 分钟时钟偏差）
            if resp.activation_ts > now + 300 {
                eprintln!(
                    "[License] activation_ts({}) 在未来（当前时间={}），可能时钟篡改，退出",
                    resp.activation_ts, now
                );
                std::process::exit(1);
            }

            // ✅ [4] 过期检查（此时 expires_at > 0 已保证）
            if now >= resp.expires_at {
                let days = (now - resp.expires_at) / 86400;
                eprintln!(
                    "[License] 密钥已过期 {} 天（到期时间: {}，当前时间: {}），请续期",
                    days, resp.expires_at, now
                );
                std::process::exit(1);
            }

            let remaining = (resp.expires_at - now) / 86400;
            println!("[License] ✅ 在线验证通过，剩余 {} 天", remaining);

            // ✅ [5] 写入本地缓存（数据合法才写入）
            storage::write_all_replicas(
                &hkey,
                &salt,
                resp.activation_ts as u64,
                resp.expires_at as u64,
            );
        }

        Err(ref e) => {
            // ── 网络失败，降级到本地缓存 ──────────────────────────────────────────
            // 已知错误码：直接拒绝，不走本地缓存
            if e == network::ERR_REVOKED {
                eprintln!("[License] 密钥已被吊销（服务端拒绝），终止");
                std::process::exit(1);
            }
            if e == network::ERR_INVALID_KEY {
                eprintln!("[License] 无效的 License Key（服务端拒绝），终止");
                std::process::exit(1);
            }
            if e == network::ERR_NOT_ACTIVATED {
                eprintln!("[License] License Key 尚未激活（服务端拒绝），终止");
                std::process::exit(1);
            }
            if e == network::ERR_EXPIRED {
                eprintln!("[License] 密钥已过期（服务端拒绝），终止");
                std::process::exit(1);
            }
            if e.starts_with("ERR-FORBIDDEN:") {
                eprintln!("[License] 密钥被区域限制 ({})，终止", e);
                std::process::exit(1);
            }

            // 网络故障（连接失败/超时等）→ 降级到本地缓存
            eprintln!("[License] 在线验证失败 ({})，使用本地缓存继续", e);

            let local_result = storage::read_local_record(&hkey, &salt);

            match local_result {
                storage::LocalReadResult::Insufficient { read_count: count } => {
                    eprintln!("[License] 本地副本不足（{}/3），无法离线验证，终止", count);
                    std::process::exit(1);
                }
                storage::LocalReadResult::Tampered { read_count: count } => {
                    eprintln!("[License] 本地副本被篡改（{}/3 副本不一致），终止", count);
                    std::process::exit(1);
                }
                storage::LocalReadResult::Success {
                    value: (local_ts, local_expires),
                    read_count: _,
                } => {
                    let local_ts_i64 = local_ts as i64;
                    let local_expires_i64 = local_expires as i64;

                    // ✅ [A] 本地记录 activation_ts 不能在未来
                    if now < local_ts_i64 {
                        eprintln!(
                            "[License] 本地缓存 activation_ts 在未来（当前={}, 激活时间={}），时钟异常，终止",
                            now, local_ts_i64
                        );
                        std::process::exit(1);
                    }

                    // ✅ [B] 本地记录 activation_ts 和 expires_at 必须 > 0
                    if local_ts == 0 || local_expires == 0 {
                        eprintln!(
                            "[License] 本地缓存数据无效（activation_ts={}, expires_at={}），终止",
                            local_ts, local_expires
                        );
                        std::process::exit(1);
                    }

                    // ✅ [C] 过期检查
                    if now >= local_expires_i64 {
                        let days = (now - local_expires_i64) / 86400;
                        eprintln!(
                            "[License] 本地缓存记录：密钥已过期 {} 天（到期: {}，当前: {}），请联网续期",
                            days, local_expires_i64, now
                        );
                        std::process::exit(1);
                    }

                    let remaining = (local_expires_i64 - now) / 86400;
                    println!(
                        "[License] ✅ 离线验证通过（本地缓存），剩余约 {} 天（请及时联网同步）",
                        remaining
                    );
                }
            }
        }
    }
}
