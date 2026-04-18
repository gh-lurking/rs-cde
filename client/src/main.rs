// src/main.rs — 程序入口，调用 license_guard 完成所有校验
use reqwest::Client;
use std::process;
mod cn_cidr;
mod geo_check;
mod license_guard;
mod network;
mod storage;

#[tokio::main]
async fn main() {
    loc_detection().await;

    // license_guard 内部使用 ureq 同步调用，在 tokio 运行时中同步阻塞是可以的
    // 若担心阻塞 tokio 线程，可用 tokio::task::spawn_blocking
    // license_guard 现在是 async fn（BUG-06 FIX），需要 .await
    license_guard::check_and_enforce().await;
    println!("✅ Your license is valid");

    // your_business_logic();
    run_client().await;
}

async fn loc_detection() {
    // println!("LOC DETECTION...\n");
    // 所有策略共用同一 HTTP Client（连接池复用）
    let client: Client = geo_check::build_http_client();
    // ── 策略 1: 公网 IP 获取 + CN CIDR 匹配 ──────────────────────────
    // 本机接口 IP 通常为内网地址（10.x/192.168.x/172.16.x），
    // 无法匹配公网 CN CIDR，必须先通过探针获取真实出口 IP。
    println!("[1] DETECTION ONE ...");
    match geo_check::check_public_ip_cidr(client.clone()).await {
        Ok(true) => {
            eprintln!("❌ Your country (region) is not supported. Please contact the support team");
            process::exit(1);
        }
        Ok(false) => println!("✅ Your country (region) is supported."),
        Err(e) => {
            eprintln!("Failure with DETECTION ONE: {e}");
            // Err(_)    => eprintln!("ERR-DTCT-ONE");
            fallback_to_cf_detection(client).await;
        }
    }
    println!("🎉 LOC DETECTION PASSED \n");
}

async fn fallback_to_cf_detection(client: Client) {
    println!("[2] FALLBACK TO DETECTION TWO ...");
    match geo_check::check_cloudflare_trace(client.clone()).await {
        Ok(true) => {
            eprintln!("❌ Your country (region) is not supported. Please contact the support team");
            process::exit(1);
        }
        Ok(false) => {
            println!("✅ Your country (region) is supported.");
        }
        // BUG-10 FIX: 两种检测都失败时退出，而不是静默放行
        Err(e) => {
            eprintln!("❌ Network unavailable: {}, Please check your internet connection", e);
            process::exit(1);
        } // Err(_) => eprintln!("ERR-DTCT-TWO")
    }
}

async fn run_client() {
    println!("🚀 Run the client now ...");
    // TODO: 在此处填写业务代码
}
