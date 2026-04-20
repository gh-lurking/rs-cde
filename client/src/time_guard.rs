// client/src/time_guard.rs — 运行时时间监控模块
// 修复：运行时时间监控，防止运行过程中修改系统时间
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
// use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static LAST_VALID_TIME: AtomicI64 = AtomicI64::new(0);
static EXPIRY_TIME: AtomicI64 = AtomicI64::new(0);
static MONITOR_STARTED: AtomicBool = AtomicBool::new(false);

/// 设置密钥过期时间（供 license_guard 调用）
pub fn set_expiry_time(expires_at: i64) {
    EXPIRY_TIME.store(expires_at, Ordering::SeqCst);
}

/// 启动时间监控线程
pub fn start_monitor() {
    if MONITOR_STARTED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return; // 已经启动
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    LAST_VALID_TIME.store(now, Ordering::SeqCst);

    thread::Builder::new()
        .name("time-guard".to_string())
        .spawn(|| {
            monitor_loop();
        })
        .expect("Failed to spawn time guard thread");

    tracing::info!("[TimeGuard] Monitor started");
}

fn monitor_loop() {
    loop {
        thread::sleep(Duration::from_secs(15)); // 每15秒检查一次

        let current = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let last = LAST_VALID_TIME.load(Ordering::SeqCst);

        // 检查时间倒退（允许 NTP 微调 60 秒）
        if current < last - 60 {
            eprintln!("❌ [TimeGuard] System time tampering detected!");
            eprintln!("   Last valid: {}, Current: {}", last, current);
            eprintln!("   Time went backwards by {} seconds", last - current);
            std::process::exit(1);
        }

        // 检查时间跳跃（允许 1 小时内的正常跳变）
        if current > last + 3600 {
            eprintln!("❌ [TimeGuard] Suspicious time jump detected!");
            eprintln!("   Last valid: {}, Current: {}", last, current);
            eprintln!("   Jumped forward by {} seconds", current - last);
            std::process::exit(1);
        }

        // 检查是否超过密钥过期时间
        let expiry = EXPIRY_TIME.load(Ordering::SeqCst);
        if expiry > 0 && current >= expiry {
            eprintln!("❌ [TimeGuard] License expired during runtime!");
            eprintln!("   Expires at: {}, Current: {}", expiry, current);
            std::process::exit(1);
        }

        LAST_VALID_TIME.store(current, Ordering::SeqCst);
    }
}
