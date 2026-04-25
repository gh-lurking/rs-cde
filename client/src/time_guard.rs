// client/src/time_guard.rs — 优化版 v3
//
// [C-03 FIX]  时间大幅跳跃（>3600s）时保守处理，校验 License 而非直接退出
// [BUG-10 FIX] watchdog Ok(_) 正常退出也触发退出
// [OPT]       MONITOR_STARTED AtomicBool 防重复启动
// [BUG-14 FIX] EXPIRY_TIME=0 时报错退出（不再静默 continue）
// [BUG-T1 FIX] ROLLBACK_TOLERANCE_SECS 默认 300s，与 TIMESTAMP_WINDOW_SECS 一致
// [BUG-CRIT-5 FIX] 大时钟跳跃后不再使用 continue 跳过过期检查
//
// [NEW-CLIENT-3] 新增 get_expiry_time() 供 license_guard 预警使用

use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static LAST_VALID_TIME: AtomicI64 = AtomicI64::new(0);
static EXPIRY_TIME: AtomicI64 = AtomicI64::new(0);
static MONITOR_STARTED: AtomicBool = AtomicBool::new(false);
static NEEDS_REVALIDATION: AtomicBool = AtomicBool::new(false);

fn rollback_tolerance_secs() -> i64 {
    std::env::var("ROLLBACK_TOLERANCE_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300)
}

pub fn set_expiry_time(expires_at: i64) {
    EXPIRY_TIME.store(expires_at, Ordering::SeqCst);
}

// [NEW-CLIENT-3] 读取当前过期时间（供预警功能使用）
pub fn get_expiry_time() -> i64 {
    EXPIRY_TIME.load(Ordering::SeqCst)
}

// time monitor
pub fn start_monitor() {
    if MONITOR_STARTED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    LAST_VALID_TIME.store(now, Ordering::SeqCst);

    let handle = thread::Builder::new()
        .name("time-guard".to_string())
        .spawn(monitor_loop)
        .expect("Failed to spawn time-guard thread");

    thread::Builder::new()
        .name("time-guard-watchdog".to_string())
        .spawn(move || match handle.join() {
            Ok(_) => {
                tracing::error!("[TimeGuard] monitor unexpectedly returned");
                std::process::exit(1);
            }
            Err(e) => {
                tracing::error!("[TimeGuard] monitor panic: {:?}", e);
                std::process::exit(1);
            }
        })
        .expect("Failed to spawn time-guard watchdog");
}

/// 主循环调用：检查是否需要重新联网验证（并清除标志）
pub fn take_revalidation_request() -> bool {
    NEEDS_REVALIDATION.swap(false, Ordering::SeqCst)
}

fn monitor_loop() {
    let tolerance = rollback_tolerance_secs();
    loop {
        thread::sleep(Duration::from_secs(15));

        let current = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let last = LAST_VALID_TIME.load(Ordering::SeqCst);
        let expiry = EXPIRY_TIME.load(Ordering::SeqCst);

        if expiry == 0 {
            tracing::error!("[TimeGuard] EXPIRY_TIME not initialized");
            std::process::exit(1);
        }

        // 时钟回拨检测
        if current < last - tolerance {
            tracing::error!("[TimeGuard] clock rollback detected");
            std::process::exit(1);
        }

        // 大时钟跳跃处理
        if current > last + 3600 {
            if current >= expiry {
                tracing::error!("[TimeGuard] expired after large clock jump");
                std::process::exit(1);
            }
            // [BUG-CRIT-5 FIX] 设置重验证标志后不跳过本轮检查
            tracing::warn!(
                "[TimeGuard] large clock jump +{}s, requesting revalidation",
                current - last
            );
            NEEDS_REVALIDATION.store(true, Ordering::SeqCst);
            LAST_VALID_TIME.store(current, Ordering::SeqCst);
            // 不 continue，继续执行下方的正常过期检查
        }

        // 正常过期检查
        if current >= expiry {
            tracing::error!("[TimeGuard] license expired");
            std::process::exit(1);
        }

        LAST_VALID_TIME.store(current, Ordering::SeqCst);
    }
}
