// client/src/time_guard.rs — 优化版 v2
// ✅ C-03 FIX: 系统挂起唤醒后不再误报退出
//             时间跳跃时先验证密钥是否过期，未过期则接受跳跃

use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
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
        return; // 防止重复启动
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    LAST_VALID_TIME.store(now, Ordering::SeqCst);

    thread::Builder::new()
        .name("time-guard".to_string())
        .spawn(monitor_loop)
        .expect("Failed to spawn time-guard thread");

    tracing::info!("[TimeGuard] Monitor started");
}

fn monitor_loop() {
    loop {
        thread::sleep(Duration::from_secs(15));

        let current = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let last = LAST_VALID_TIME.load(Ordering::SeqCst);
        let expiry = EXPIRY_TIME.load(Ordering::SeqCst);

        // ── 1. 时间倒退检查（允许 60 s NTP 微调）──────────────────────
        if current < last - 60 {
            eprintln!(
                "❌ [TimeGuard] Time went backwards: last={} current={} diff={}s",
                last,
                current,
                last - current
            );
            std::process::exit(1);
        }

        // ── 2. 时间跳跃处理（✅ C-03 FIX）────────────────────────────
        //    原逻辑：跳跃 >1h 直接退出（合盖唤醒必中招）
        //    新逻辑：跳跃时先检查密钥是否已过期
        if current > last + 3600 {
            tracing::warn!(
                "[TimeGuard] Time jump detected: {}s (suspend/resume?). Checking expiry...",
                current - last
            );

            if expiry > 0 && current >= expiry {
                // 跳跃后密钥已过期 → 退出
                eprintln!(
                    "❌ [TimeGuard] License expired during suspend. expired_at={} current={}",
                    expiry, current
                );
                std::process::exit(1);
            }

            // 跳跃但密钥仍有效 → 接受新时间，继续运行
            tracing::info!(
                "[TimeGuard] Time jump accepted (license still valid). Updating baseline."
            );
            LAST_VALID_TIME.store(current, Ordering::SeqCst);
            continue;
        }

        // ── 3. 正常周期：检查密钥是否到期 ────────────────────────────
        if expiry > 0 && current >= expiry {
            eprintln!(
                "❌ [TimeGuard] License expired during runtime! expired_at={} current={}",
                expiry, current
            );
            std::process::exit(1);
        }

        LAST_VALID_TIME.store(current, Ordering::SeqCst);
    }
}
