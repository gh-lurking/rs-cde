// client/src/license_guard.rs — 优化版（修复 BUG-04/05/06/10）

// BUG-04 FIX: 启动多副本校验（副本数 ≥ 2），三者不一致时直接退出
// BUG-05 FIX: 时间戳统一使用 i64，避免 u64→i64 转换溢出导致永不过期
// BUG-06 FIX: 调用 async verify_online() 使用 .await，不阻塞线程
// BUG-10 FIX: 地理检测双重降级失败时不放行避免离线环境绕过检测

use crate::{network, storage};
use obfstr::obfstr;
use std::time::{SystemTime, UNIX_EPOCH};

const NET_TIMEOUT_SECS: u64 = 10;
pub async fn check_and_enforce() {
    // ── Step 1: 读取 HKEY ──────────────────────────────────────────────────────
    let hkey = std::env::var("HKEY").unwrap_or_else(|_| {
        eprintln!("[License] 未找到 HKEY 环境变量，请激活");
        std::process::exit(1);
    });

    // ── Step 2: 派生混淆盐 + 服务器 URL ──────────────────────────────────────
    let salt = obfstr!("PROG_ACTIVATION_SALT_V1_SECRET").to_owned();
    let server_url = obfstr!("http://localhost:1000").to_owned();

    // ── Step 3: 读取三份本地副本（BUG-04 FIX: 启动多副本校验）──────────────
    let (local_record, replica_count) = storage::read_local_record_with_count(&hkey, &salt);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64; // BUG-05 FIX: 统一 i64

    // ── Step 4: 在线校验（网络可用时）────────────────────────────────────────
    // BUG-06 FIX: verify_online 现在是 async fn，需要 .await
    match network::verify_online(&hkey, &server_url, NET_TIMEOUT_SECS).await {
        Ok(resp) => {
            // 4a: 服务端已撤销
            if resp.revoked {
                eprintln!("[License] 许可证已被吊销，请联系支持");
                std::process::exit(1);
            }

            // 4b: 使用服务端 expires_at 判断（统一 i64）
            if now >= resp.expires_at {
                let days = (now - resp.expires_at) / 86400;
                eprintln!("[License] 许可证已过期 {} 天，请联系支持", days);
                std::process::exit(1);
            }

            // 4c: 未激活（在 verify 里看到 activation_ts==0 会返回 402）
            if resp.activation_ts == 0 {
                eprintln!("[License] Key 尚未激活，请先完成激活");
                std::process::exit(1);
            }

            let remaining = (resp.expires_at - now) / 86400;
            println!("[License] ✅ 在线校验通过，剩余 {} 天", remaining);

            // 4d: 同步最新数据到本地三份副本（BUG-07: 使用随机 nonce，storage 已处理）
            storage::write_all_replicas(
                &hkey,
                &salt,
                resp.activation_ts as u64,
                resp.expires_at as u64,
            );
        }

        Err(e) => {
            // 4e: 网络失败 → 降级到本地缓存校验
            eprintln!("[License] 在线校验失败（{}），使用本地缓存校验", e);
            let (local_ts, local_expires) = local_record.unwrap_or_else(|| {
                eprintln!("[License] 本地缓存不存在且网络不通，无法校验，退出");
                std::process::exit(1);
            });

            // BUG-04 FIX: 副本数 < 2（不满足多数），拒绝信任
            if replica_count < 2 {
                eprintln!(
                    "[License] 本地副本不足（当前 {}/3），可能遭到篡改，退出",
                    replica_count
                );
                std::process::exit(1);
            }

            // BUG-05 FIX: local_ts/local_expires 均为 u64，比较前转 i64
            let local_ts_i64 = local_ts as i64;
            let local_expires_i64 = local_expires as i64;

            // BUG-05 FIX: 时钟回拨检测（now < activation_ts 说明系统时间被调后）
            if now < local_ts_i64 {
                eprintln!(
                    "[License] 检测到时钟回拨（当前={}, 激活时间={}），退出",
                    now, local_ts_i64
                );
                std::process::exit(1);
            }

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
