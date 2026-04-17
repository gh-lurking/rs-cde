// src/main.rs — 程序入口，调用 license_guard 完成所有校验
use reqwest::Client;
use std::process;
mod cn_cidr;
mod geo_check;
mod license_guard;
mod network;
mod storage;

fn main() {
    loc_detection();

    license_guard::check_and_enforce();
    println!("✅ Your license is valid");

    // your_business_logic();
    run_client();
}

#[tokio::main]
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
        Ok(false) => println!("✅ Your country (region) is supported."),
        Err(e) => eprintln!("Failure with DETECTION TWO: {e}"),
        // Err(_) => eprintln!("ERR-DTCT-TWO"),
    }
}

fn run_client() {
    println!("🚀 Run the client now ...");
    // TODO: 在此处填写业务代码
}
