// client/src/main.rs — 优化版
// ✅ BUG-06 FIX: license_guard::check_and_enforce() 是 async fn，需 .await
// ✅ BUG-10 FIX: 地理检测两层降级，网络不可用时退出而非忽略
use reqwest::Client;
use std::process;
mod cn_cidr;
mod geo_check;
mod license_guard;
mod network;
mod storage;
mod time_guard;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_env_filter("info").init();

    loc_detection().await;
    // 系统时间合理性校验（阈值 300 s，与服务端时间窗口一致）
    if let Err(e) = network::validate_system_time().await {
        eprintln!("❌ System time validation failed: {e}");
        process::exit(1);
    }

    license_guard::check_and_enforce().await;
    // ✅ NEW: 启动运行时时间监控
    time_guard::start_monitor();
    println!("✅ Your license is valid");

    run_client().await;
}

async fn loc_detection() {
    // 复用同一 HTTP Client（已有连接池，避免重复创建）
    let client: Client = geo_check::build_http_client();

    // ── 检测 1: 公网 IP + CN CIDR 匹配 ────────────────────────────────────
    println!("[1] DETECTION ONE ...");
    match geo_check::check_public_ip_cidr(client.clone()).await {
        Ok(true) => {
            eprintln!("❌ Your country (region) is not supported. Please contact the support team");
            process::exit(1);
        }
        Ok(false) => {
            println!("✅ Your country (region) is supported.")
        }
        Err(e) => {
            eprintln!("Failure with DETECTION ONE: {e}");
            fallback_to_cf_detection(client).await;
        }
    }
    println!("🌍 LOC DETECTION PASSED");
}

async fn fallback_to_cf_detection(client: Client) {
    println!("[2] FALLBACK TO DETECTION TWO ...");
    match geo_check::check_cloudflare_trace(client).await {
        Ok(true) => {
            eprintln!("❌ Your country (region) is not supported. Please contact the support team");
            process::exit(1);
        }
        Ok(false) => {
            println!("✅ Your country (region) is supported.");
        }
        // ✅ BUG-10 FIX: 两层检测都失败时，不忽略错误，须退出
        Err(e) => {
            eprintln!(
                "❌ Network unavailable: {}, Please check your internet connection",
                e
            );
            process::exit(1);
        }
    }
}

async fn run_client() {
    println!("🚀 Run the client now ...");
    // TODO: 在此处添加实际业务逻辑
}
