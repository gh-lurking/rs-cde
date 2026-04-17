// client/src/license_guard.rs — 优化版（修复 BUG-04/05/06/10）

// BUG-04 FIX: 多数票逻辑改为严格多数（>N/2），三副本不一致时触发修复写入
// BUG-05 FIX: 时钟回拨检测后立即 exit(1)
// BUG-06 FIX: 移除 activate_online() 死代码；统一使用单运行时

use crate::{network, storage};
use obfstr::obfstr;
use std::time::{SystemTime, UNIX_EPOCH};

const NET_TIMEOUT_SECS: u64 = 10;

pub fn check_and_enforce() {
    // ── Step 1: 读取 HKEY ────────────────────────────────────────────────────
    let hkey = std::env::var("HKEY").unwrap_or_else(|_| {
        eprintln!("[License] 未设置 HKEY 环境变量，程序终止");

        std::process::exit(1);
    });

    // ── Step 2: 编译期混淆常量 ────────────────────────────────────────────────
    let salt = obfstr!("PROG_ACTIVATION_SALT_V1_SECRET").to_owned();
    let server_url = obfstr!("http://localhost:1000").to_owned();

    // ── Step 3: 读取三重本地存储（BUG-04 FIX: 严格多数票）──────────────────
    let (local_record, replica_count) = storage::read_local_record_with_count(&hkey, &salt);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // ── Step 4: 联网校验（主要路径）──────────────────────────────────────────
    match network::verify_online(&hkey, &server_url, NET_TIMEOUT_SECS) {
        Ok(resp) => {
            // 4a: 服务端明确吊销
            if resp.revoked {
                eprintln!("[License] 授权已被吊销，程序终止");
                std::process::exit(1);
            }

            // 4b: 使用服务端 expires_at 判断过期
            if now as i64 >= resp.expires_at {
                let days = (now as i64 - resp.expires_at) / 86400;
                eprintln!("[License] 授权已过期 {} 天，程序终止", days);
                std::process::exit(1);
            }

            // 4c: 未激活（理论上不应到达此分支，服务端 /verify 对未激活返回 402）
            if resp.activation_ts == 0 {
                eprintln!("[License] Key 尚未激活，请运行激活流程后重试");
                std::process::exit(1);
            }

            let remaining = (resp.expires_at - now as i64) / 86400;
            println!("[License] ✅ 在线校验通过，剩余 {} 天", remaining);

            // 4d: 同步最新数据到本地三副本（BUG-07: 使用随机 nonce，storage 负责）
            storage::write_all_replicas(
                &hkey,
                &salt,
                resp.activation_ts as u64,
                resp.expires_at as u64,
            );
        }

        Err(e) => {
            // 4e: 联网失败 → 降级纯本地校验
            eprintln!("[License] 联网校验失败（{}），回退到本地校验", e);
            let (local_ts, local_expires) = local_record.unwrap_or_else(|| {
                eprintln!("[License] 本地无激活记录且无法联网，程序终止");

                std::process::exit(1);
            });

            // BUG-04 FIX: 若三副本读取数 < 2（不足多数），拒绝通过
            if replica_count < 2 {
                eprintln!(
                    "[License] 本地副本不足（读到 {}/3），数据可能被篡改，程序终止",
                    replica_count
                );

                std::process::exit(1);
            }

            // BUG-05 FIX: 时钟回拨时立即退出，而不是仅打印警告
            if now < local_ts {
                eprintln!(
                    "[License] 系统时钟回拨（当前={}, 激活时={}），程序终止",
                    now, local_ts
                );

                std::process::exit(1);
            }

            if now as i64 >= local_expires as i64 {
                let days = (now as i64 - local_expires as i64) / 86400;
                eprintln!("[License] 授权已过期 {} 天（本地缓存），程序终止", days);
                std::process::exit(1);
            }

            let remaining = (local_expires as i64 - now as i64) / 86400;
            println!(
                "[License] ✅ 本地校验通过（离线模式），剩余约 {} 天",
                remaining
            );
        }
    }
}
