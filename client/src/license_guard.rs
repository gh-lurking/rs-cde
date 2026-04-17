// client/src/license_guard.rs — 核心校验逻辑
//
// ✅ 变更1: 删除 VALID_KEYS 静态集合 (OnceLock<HashSet<&str>>)
//   原来客户端在二进制中硬编码了所有合法 key，
//   现在 key 的合法性完全由服务端决定（预置在 DB 中）。
//   客户端仅持有自己的 HKEY，不持有其他 key 的任何信息。
//
// ✅ 变更2: 删除本地 valid_keys() 检查（第一步校验）
//   原逻辑第一步是 if !valid_keys().contains(&hkey)，
//   现在跳过此步，直接进入本地三副本读取 + 联网校验。
//
// ✅ 变更3: expires_at 由服务端权威给出
//   原来用 now - activation_ts > EXPIRE_SECS (客户端常量) 判断过期，
//   现在使用服务端返回的 expires_at 字段：
//     if now >= resp.expires_at { exit(1) }
//   本地降级模式下仍用本地 expires_at 缓存（首次联网时写入本地副本）。
//
// ✅ 变更4: expires_at 也写入本地三副本（与 activation_ts 一起存储），
//   网络不可达时使用本地缓存的 expires_at 判断是否过期，
//   彻底移除客户端常量 EXPIRE_SECS（避免二进制内出现过期时长常量）。
//
// 保留不变的逻辑：
//   - HKEY 从环境变量 HKEY 读取
//   - obfstr! 混淆 SALT 和 SERVER_URL
//   - AES-GCM 三副本本地存储（storage 模块）
//   - 多数票读取 activation_ts
//   - 时钟回拨检测（now < local_ts）
//   - 网络不可达时降级为纯本地校验
//   - 任何校验失败直接 exit(1)

use std::time::{SystemTime, UNIX_EPOCH};
use obfstr::obfstr;
use crate::{storage, network};

/// 联网超时：3 秒，超时后降级为纯本地校验
const NET_TIMEOUT_SECS: u64 = 3;

// ✅ 变更1: 完全删除以下代码块（原版中存在）：
//
//   static VALID_KEYS: OnceLock<HashSet<&'static str>> = OnceLock::new();
//   fn valid_keys() -> &'static HashSet<&'static str> {
//       VALID_KEYS.get_or_init(|| {
//           ["HKEY-AAAA-1111-XXXX", ...].into_iter().collect()
//       })
//   }

/// 主校验入口 —— 任何校验失败直接 exit(1)
pub fn check_and_enforce() {
    // ── Step 1: 读取 HKEY 环境变量 ────────────────────────────────────────────
    let hkey = std::env::var("HKEY").unwrap_or_else(|_| {
        eprintln!("[License] 未设置 HKEY 环境变量，程序终止");
        std::process::exit(1);
    });

    // ✅ 变更2: 删除以下本地白名单检查（原版第二步）：
    //
    //   if !valid_keys().contains(hkey.as_str()) {
    //       eprintln!("[License] 无效的授权秘钥，程序终止");
    //       std::process::exit(1);
    //   }
    //
    // key 的合法性由服务端数据库决定（/activate 和 /verify 均会校验）。

    // ── Step 2: obfstr 派生 SALT 和 SERVER_URL（编译期混淆）─────────────────
    let salt       = obfstr!("PROG_ACTIVATION_SALT_V1_SECRET").to_owned();
    let server_url = obfstr!("http://localhost:1000").to_owned();

    // ── Step 3: 读取三重本地存储（activation_ts + expires_at）───────────────
    // storage 模块返回 (activation_ts, expires_at) 对，
    // 均使用 AES-128-GCM 加密后以多数票原则读取。
    let local_record = storage::read_local_record(&hkey, &salt);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH).unwrap().as_secs();

    // ── Step 4: 联网校验（主要路径）──────────────────────────────────────────
    match network::verify_online(&hkey, &server_url, NET_TIMEOUT_SECS) {
        Ok(resp) => {
            // ── 4a: 服务端明确吊销 ─────────────────────────────────────────
            if resp.revoked {
                eprintln!("[License] 授权已被吊销，程序终止");
                std::process::exit(1);
            }

            // ── 4b: ✅ 变更3 — 使用服务端 expires_at 判断过期 ──────────────
            // 原版：if now.saturating_sub(server_ts) > EXPIRE_SECS { exit(1) }
            // 新版：if now >= resp.expires_at { exit(1) }
            if now as i64 >= resp.expires_at {
                let expired_days = (now as i64 - resp.expires_at) / 86400;
                eprintln!(
                    "[License] 授权已过期 {} 天（服务端 expires_at），程序终止",
                    expired_days
                );
                std::process::exit(1);
            }

            let remaining = (resp.expires_at - now as i64) / 86400;
            println!("[License] ✅ 在线校验通过，剩余 {} 天", remaining);

            // ── 4c: ✅ 变更4 — 将服务端 expires_at 同步到本地三副本 ─────────
            // 本地存储同时持久化 activation_ts 和 expires_at，
            // 供网络不可达时的降级校验使用。
            storage::write_all_replicas(
                &hkey, &salt,
                resp.activation_ts as u64,
                resp.expires_at as u64,
            );
        }

        Err(e) => {
            // ── 4d: 联网失败 → 降级纯本地校验 ────────────────────────────
            eprintln!("[License] 联网校验失败（{}），回退到本地校验", e);

            let (local_ts, local_expires) = local_record.unwrap_or_else(|| {
                eprintln!("[License] 本地无激活记录且无法联网，程序终止");
                std::process::exit(1);
            });

            // 时钟回拨检测
            if now < local_ts {
                eprintln!("[License] 检测到时钟回拨，程序终止");
                std::process::exit(1);
            }

            // ✅ 变更3（本地降级路径）：使用本地缓存的 expires_at 判断过期
            // 原版：if now - ts > EXPIRE_SECS { exit(1) }
            // 新版：if now >= local_expires { exit(1) }
            if now as i64 >= local_expires as i64 {
                let expired_days = (now as i64 - local_expires as i64) / 86400;
                eprintln!(
                    "[License] 授权已过期 {} 天（本地缓存 expires_at），程序终止",
                    expired_days
                );
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