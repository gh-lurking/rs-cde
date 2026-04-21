// client/src/time_guard.rs — 优化版 v3
//
// ✅ C-03 FIX: 挂起唤醒后不再误退出；时间跳跃先验过期，未过期则接受
// ✅ BUG-10 FIX: 添加 watchdog 线程，监控 time-guard 意外退出

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

    // ✅ BUG-10 FIX: 启动 time-guard 并用 watchdog 监控其存活
    let handle = thread::Builder::new()
        .name("time-guard".to_string())
        .spawn(monitor_loop)
        .expect("Failed to spawn time-guard thread");

    // watchdog 线程：time-guard 一旦退出（正常或 panic），立即终止进程
    thread::Builder::new()
        .name("time-guard-watchdog".to_string())
        .spawn(move || match handle.join() {
            Ok(_) => {
                eprintln!("❌ [TimeGuard] 监控线程意外退出，终止进程");
                std::process::exit(1);
            }

            Err(_) => {
                eprintln!("❌ [TimeGuard] 监控线程 panic，终止进程");
                std::process::exit(1);
            }
        })
        .expect("Failed to spawn time-guard watchdog");

    tracing::info!("[TimeGuard] 监控线程已启动（含 watchdog）");
}

fn monitor_loop() {
    loop {
        thread::sleep(Duration::from_secs(15));

        // ✅ 使用 unwrap_or_default 避免潜在 panic
        let current = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let last = LAST_VALID_TIME.load(Ordering::SeqCst);
        let expiry = EXPIRY_TIME.load(Ordering::SeqCst);

        // ── 1. 时间倒退检查（允许 60s NTP 微调）──────────────────────────
        if current < last - 60 {
            eprintln!(
                "❌ [TimeGuard] 时间倒退: last={} current={} diff={}s",
                last,
                current,
                last - current
            );

            std::process::exit(1);
        }

        // ── 2. ✅ C-03 FIX：时间跳跃处理（挂起/唤醒）────────────────────
        if current > last + 3600 {
            tracing::warn!(
                "[TimeGuard] 时间跳跃 {}s（可能是挂起唤醒），检查过期状态...",
                current - last
            );

            if expiry > 0 && current >= expiry {
                // 跳跃后密钥已过期 → 退出
                eprintln!(
                    "❌ [TimeGuard] 挂起期间 License 已过期。expired_at={} now={}",
                    expiry, current
                );
                std::process::exit(1);
            }

            // 跳跃但密钥仍有效 → 接受新时间，继续运行
            tracing::info!("[TimeGuard] 时间跳跃但 License 仍有效，继续运行");
            LAST_VALID_TIME.store(current, Ordering::SeqCst);
            continue;
        }

        // ── 3. 正常周期：检查密钥是否到期 ──────────────────────────────
        if expiry > 0 && current >= expiry {
            eprintln!(
                "❌ [TimeGuard] License 运行时到期！expired_at={} now={}",
                expiry, current
            );
            std::process::exit(1);
        }
        LAST_VALID_TIME.store(current, Ordering::SeqCst);
    }
}
