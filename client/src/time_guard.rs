// client/src/time_guard.rs — 优化版 v6
//
// [C-03 FIX]  时间正向大跳变（>3600s）后更新基准，避免永久误报
// [BUG-10 FIX] watchdog Ok(_) 分支也视为异常
// [OPT]        MONITOR_STARTED AtomicBool 防止重复启动
// [BUG-14 FIX] 添加 EXPIRY_TIME 零值检查
// [BUG-T1 FIX] ROLLBACK_TOLERANCE_SECS 改为 300s，与服务端 TIMESTAMP_WINDOW_SECS 一致
//              可通过 ROLLBACK_TOLERANCE_SECS 环境变量覆盖

use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static LAST_VALID_TIME: AtomicI64 = AtomicI64::new(0);
static EXPIRY_TIME: AtomicI64 = AtomicI64::new(0);
static MONITOR_STARTED: AtomicBool = AtomicBool::new(false);

// [BUG-T1 FIX] 与服务端 TIMESTAMP_WINDOW_SECS 保持一致（300s）
// 原值 60s 会导致 NTP 大步回拨（60~300s 范围）误判为时钟篡改而终止进程
fn rollback_tolerance_secs() -> i64 {
    std::env::var("ROLLBACK_TOLERANCE_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300)
}

pub fn set_expiry_time(expires_at: i64) {
    EXPIRY_TIME.store(expires_at, Ordering::SeqCst);
}

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

    // watchdog：time-guard 线程任何退出都视为异常
    thread::Builder::new()
        .name("time-guard-watchdog".to_string())
        .spawn(move || {
            match handle.join() {
                // [BUG-10 FIX] Ok(_) 也视为异常（永久循环不应正常退出）
                Ok(_) => {
                    tracing::error!("time-guard 线程意外退出，终止进程");
                    std::process::exit(1);
                }
                Err(_) => {
                    tracing::error!("time-guard 线程 panic，终止进程");
                    std::process::exit(1);
                }
            }
        })
        .expect("Failed to spawn time-guard watchdog");

    tracing::info!(
        "[TimeGuard] 监控线程已启动（含 watchdog），回拨容差={}s",
        rollback_tolerance_secs()
    );
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

        // [BUG-14 FIX] EXPIRY_TIME 零值检查（未设置前跳过检测）
        if expiry == 0 {
            tracing::debug!("[TimeGuard] 等待 EXPIRY_TIME 设置...");
            continue;
        }

        // 1. 时间回拨检测
        if current < last - tolerance {
            tracing::error!(
                "时间回拨: last={} current={} diff={}s > tolerance={}s，终止进程",
                last,
                current,
                last - current,
                tolerance
            );
            std::process::exit(1);
        }

        // 2. [C-03 FIX] 大幅正向跳变（休眠唤醒 / NTP 大步校时）
        if current > last + 3600 {
            tracing::warn!(
                "[TimeGuard] 时间向前跳变 {}s，检查 License...",
                current - last
            );
            if current >= expiry {
                tracing::error!(
                    "跳变后 License 已过期: expired_at={} now={}，终止进程",
                    expiry,
                    current
                );
                std::process::exit(1);
            }
            // [C-03 FIX] 更新基准，避免下轮循环继续触发大跳变告警
            LAST_VALID_TIME.store(current, Ordering::SeqCst);
            tracing::info!("[TimeGuard] License 未过期，更新基准时间 → {}", current);
            continue;
        }

        // 3. 正常到期检测
        if current >= expiry {
            tracing::error!(
                "License 到期: expired_at={} now={}，终止进程",
                expiry,
                current
            );
            std::process::exit(1);
        }

        LAST_VALID_TIME.store(current, Ordering::SeqCst);
    }
}
