// client/src/time_guard.rs -- 优化版 v4
//
// C-03 FIX: 时间正向大跳变后更新 LAST_VALID_TIME，避免永久误报
// BUG-10 FIX: watchdog Ok(_) 分支改为 tracing::error! + exit
//             区分正常退出（也是异常）与 panic
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static LAST_VALID_TIME: AtomicI64 = AtomicI64::new(0);
static EXPIRY_TIME: AtomicI64 = AtomicI64::new(0);
static MONITOR_STARTED: AtomicBool = AtomicBool::new(false);

pub fn set_expiry_time(expires_at: i64) {
    EXPIRY_TIME.store(expires_at, Ordering::SeqCst);
}

pub fn start_monitor() {
    if MONITOR_STARTED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return; // 防止重复启动
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    LAST_VALID_TIME.store(now, Ordering::SeqCst);

    // 启动 time-guard 线程
    let handle = thread::Builder::new()
        .name("time-guard".to_string())
        .spawn(monitor_loop)
        .expect("Failed to spawn time-guard thread");

    // watchdog: 监控 time-guard 线程，任何退出都视为异常
    thread::Builder::new()
        .name("time-guard-watchdog".to_string())
        .spawn(move || match handle.join() {
            // BUG-10 FIX: Ok(_) 也视为异常
            // monitor_loop 是永久循环，正常退出即代码 Bug
            Ok(_) => {
                tracing::error!("time-guard 线程意外退出（永久循环不应正常退出）");
                std::process::exit(1);
            }
            Err(_) => {
                tracing::error!("time-guard 线程 panic，终止进程");
                std::process::exit(1);
            }
        })
        .expect("Failed to spawn time-guard watchdog");

    tracing::info!("[TimeGuard] 监控线程已启动（含 watchdog）");
}

fn monitor_loop() {
    loop {
        thread::sleep(Duration::from_secs(15));

        // unwrap_or_default 避免 panic
        let current = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let last = LAST_VALID_TIME.load(Ordering::SeqCst);
        let expiry = EXPIRY_TIME.load(Ordering::SeqCst);

        // 1. 时间回拨检测（容差 60s NTP 微调）
        if current < last - 60 {
            tracing::error!(
                "时间回拨: last={} current={} diff={}s",
                last,
                current,
                last - current
            );
            std::process::exit(1);
        }

        // 2. C-03 FIX: 大幅正向跳变（休眠唤醒 / NTP 大步校时）
        if current > last + 3600 {
            tracing::warn!(
                "[TimeGuard] 时间向前跳变 {}s，检查 License...",
                current - last
            );

            if expiry > 0 && current >= expiry {
                tracing::error!(
                    "跳变后 License 已过期: expired_at={} now={}",
                    expiry,
                    current
                );
                std::process::exit(1);
            }

            // C-03 FIX: 更新基准，避免下轮循环继续触发大跳变告警
            LAST_VALID_TIME.store(current, Ordering::SeqCst);
            tracing::info!("[TimeGuard] License 未过期，更新基准时间");
            continue;
        }

        // 3. 正常到期检测
        if expiry > 0 && current >= expiry {
            tracing::error!("License 到期: expired_at={} now={}", expiry, current);
            std::process::exit(1);
        }

        LAST_VALID_TIME.store(current, Ordering::SeqCst);
    }
}
