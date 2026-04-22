// client/src/time_guard.rs
//
// [C-03 FIX]  时间大幅跳跃（>3600s）时保守处理，校验 License 而非直接退出
// [BUG-10 FIX] watchdog Ok(_) 正常退出也触发退出（含清晰注释）
// [OPT]       MONITOR_STARTED AtomicBool 防重复启动
// [BUG-14 FIX] EXPIRY_TIME=0 时报错退出（不再静默 continue）
// [BUG-T1 FIX] ROLLBACK_TOLERANCE_SECS 默认 300s，与 TIMESTAMP_WINDOW_SECS 一致
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static LAST_VALID_TIME: AtomicI64 = AtomicI64::new(0);
static EXPIRY_TIME: AtomicI64 = AtomicI64::new(0);
static MONITOR_STARTED: AtomicBool = AtomicBool::new(false);

// [BUG-T1 FIX] 默认 300s，与 TIMESTAMP_WINDOW_SECS 对齐
// 说明：60s 足以覆盖 NTP 调整（60~300s 范围），防止闰秒/夏令时误触发
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

    // watchdog: time-guard 线程退出时强制退出进程
    thread::Builder::new()
        .name("time-guard-watchdog".to_string())
        .spawn(move || {
            match handle.join() {
                // [BUG-10 FIX] Ok(_)：monitor_loop 是无限 loop，正常情况不应返回
                // 若返回说明内部 process::exit 之外的路径被触发（不可达，防御性处理）
                Ok(_) => {
                    tracing::error!("[TimeGuard] time-guard 线程意外返回，退出进程");
                    std::process::exit(1);
                }
                Err(e) => {
                    tracing::error!("[TimeGuard] time-guard 线程 panic: {:?}，退出进程", e);
                    std::process::exit(1);
                }
            }
        })
        .expect("Failed to spawn time-guard watchdog");

    tracing::info!(
        "[TimeGuard] 监控线程已启动（含 watchdog），回拨容忍={}s",
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

        // [BUG-14 FIX] EXPIRY_TIME=0 说明 set_expiry_time 未被调用，属启动流程错误
        if expiry == 0 {
            tracing::error!("[TimeGuard] EXPIRY_TIME 未初始化（set_expiry_time 未被调用），退出");
            std::process::exit(1);
        }

        // 1. 时钟回拨检测
        if current < last - tolerance {
            tracing::error!(
                "[TimeGuard] 时钟回拨: last={} current={} diff={}s > tolerance={}s，退出",
                last,
                current,
                last - current,
                tolerance
            );
            std::process::exit(1);
        }

        // 2. [C-03 FIX] 时钟大幅跳跃（休眠/NTP 大跳）保守处理
        if current > last + 3600 {
            tracing::warn!(
                "[TimeGuard] 时钟大幅跳跃 {}s，校验 License...",
                current - last
            );
            if current >= expiry {
                tracing::error!(
                    "[TimeGuard] 跳跃后 License 已过期: expired_at={} now={}，退出",
                    expiry,
                    current
                );
                std::process::exit(1);
            }
            // [C-03 FIX] 更新 LAST_VALID_TIME，避免下次循环继续触发大跳告警
            LAST_VALID_TIME.store(current, Ordering::SeqCst);
            tracing::info!(
                "[TimeGuard] License 跳跃后仍有效，更新基准时间 → {}",
                current
            );
            continue;
        }

        // 3. 到期检测
        if current >= expiry {
            tracing::error!(
                "[TimeGuard] License 到期: expired_at={} now={}，退出",
                expiry,
                current
            );
            std::process::exit(1);
        }

        LAST_VALID_TIME.store(current, Ordering::SeqCst);
    }
}
