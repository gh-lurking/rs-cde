// client/src/license_guard.rs — 优化版 v3
// [FIX-1] ERR_EXPIRED 作为业务拒绝处理，立即退出，不走离线缓存
// CRIT-3 FIX: 业务拒绝错误码触发立即退出
// MINOR-1 FIX: 本地副本读取延迟到在线校验失败后（lazy evaluation）
use crate::{network, storage};
use obfstr::obfstr;
use std::time::{SystemTime, UNIX_EPOCH};

pub async fn check_and_enforce() {
    let hkey = std::env::var("HKEY").unwrap_or_else(|_| {
        eprintln!("[License] 未找到 HKEY 环境变量，请激活");
        std::process::exit(1);
    });

    let salt = obfstr!("PROG_ACTIVATION_SALT_V1_SECRET").to_owned();
    let server_url = obfstr!("http://localhost:1000").to_owned();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    match network::verify_online(&hkey, &server_url).await {
        Ok(resp) => {
            // 服务端已撤销
            if resp.revoked {
                eprintln!("[License] 许可证已被吊销，请联系支持");
                std::process::exit(1);
            }

            // 服务端已过期
            if now >= resp.expires_at {
                let days = (now - resp.expires_at) / 86400;
                eprintln!("[License] 许可证已过期 {} 天，请联系支持", days);
                std::process::exit(1);
            }

            // 未激活
            if resp.activation_ts == 0 {
                eprintln!("[License] Key 尚未激活，请先完成激活");
                std::process::exit(1);
            }

            let remaining = (resp.expires_at - now) / 86400;
            println!("[License] ✅ 在线校验通过，剩余 {} 天", remaining);

            // 同步最新数据到本地三份副本
            if resp.activation_ts > 0 && resp.expires_at > now {
                storage::write_all_replicas(
                    &hkey,
                    &salt,
                    resp.activation_ts as u64,
                    resp.expires_at as u64,
                );
            } else {
                tracing::warn!(
                    "[License] 服务端返回异常时间戳，跳过本地缓存写入 activation_ts={} expires_at={}",
                    resp.activation_ts,
                    resp.expires_at
                );
            }
        }

        Err(ref e) => {
            // CRIT-3 FIX: 业务明确拒绝 → 立即退出，不走离线缓存
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
            // [FIX-1] 新增: 过期也是业务拒绝，不走离线缓存
            if e == network::ERR_EXPIRED {
                eprintln!("[License] 许可证已过期（服务端确认），立即退出");
                std::process::exit(1);
            }

            // 真正的网络错误 → 降级到本地缓存
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
