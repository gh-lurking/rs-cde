// client/src/license_guard.rs — 完整优化版
// 原有修复: BUG-04/05/06/F/NEW-6
// 新增修复: BUG-NEW-C(用枚举精确区分副本状态)
//           BUG-NEW-E(写缓存前校验 i64 正值，防 as u64 负值转超大数)

use crate::{network, storage};
use obfstr::obfstr;
use std::time::{SystemTime, UNIX_EPOCH};

// BUG-06 FIX: 声明为 async fn
pub async fn check_and_enforce() {
    // Step 1: 读取 HKEY
    let hkey = std::env::var("HKEY").unwrap_or_else(|_| {
        eprintln!("[License] 未找到 HKEY 环境变量，请激活");
        std::process::exit(1);
    });

    // Step 2: 派生混淆盐 + 服务器 URL
    let salt = obfstr!("PROG_ACTIVATION_SALT_V1_SECRET").to_owned();
    let server_url = obfstr!("http://localhost:1000").to_owned();

    // Step 3: 读取三份本地副本
    // BUG-NEW-C FIX: 使用枚举返回值，精确区分「副本不足」「投票失败」「成功」
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64; // BUG-05 FIX: 统一 i64

    let local_result = storage::read_local_record(&hkey, &salt);

    // Step 4: 在线校验（BUG-06 FIX: async .await）
    match network::verify_online(&hkey, &server_url).await {
        Ok(resp) => {
            // 4a: 服务端已撤销
            if resp.revoked {
                eprintln!("[License] 许可证已被吊销，请联系支持");
                std::process::exit(1);
            }

            // 4b: 服务端已过期（BUG-05 FIX: 统一 i64）
            if now >= resp.expires_at {
                let days = (now - resp.expires_at) / 86400;
                eprintln!("[License] 许可证已过期 {} 天，请联系支持", days);
                std::process::exit(1);
            }

            // 4c: 未激活
            if resp.activation_ts == 0 {
                eprintln!("[License] Key 尚未激活，请先完成激活");
                std::process::exit(1);
            }

            let remaining = (resp.expires_at - now) / 86400;
            println!("[License] ✅ 在线校验通过，剩余 {} 天", remaining);

            // 4d: 同步最新数据到本地三份副本
            // BUG-NEW-E FIX: 写缓存前校验时间戳合法性，防止负值 as u64 = 超大数
            if resp.activation_ts > 0 && resp.expires_at > now {
                storage::write_all_replicas(
                    &hkey,
                    &salt,
                    resp.activation_ts as u64,
                    resp.expires_at as u64,
                );
            } else {
                tracing::warn!(
                    "[License] 服务端返回异常时间戳，跳过本地缓存写入                      activation_ts={} expires_at={}",
                    resp.activation_ts,
                    resp.expires_at
                );
            }
        }

        Err(e) => {
            eprintln!("[License] 在线校验失败（{}），使用本地缓存校验", e);

            // BUG-NEW-C FIX: 枚举精确处理各种失败场景
            match local_result {
                storage::LocalReadResult::Insufficient{read_count: count} => {
                    eprintln!(
                        "[License] 本地副本不足（{}/3），可能首次运行未缓存或文件丢失，退出",
                        count
                    );
                    std::process::exit(1);
                }
                storage::LocalReadResult::Tampered{read_count: count} => {
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
