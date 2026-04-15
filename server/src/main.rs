// server/src/main.rs — Axum Web 服务入口
// ✅ 修复1: 补齐三个 mod 声明（之前 handlers.rs 引用 db 时找不到模块）
mod db;       // ← 必须在此声明，handlers.rs 才能通过 crate::db 访问
mod handlers; // ← 同上
mod auth;     // ← 同上

use axum::{
    routing::{get, post, delete},
    Router,
    Extension,
};
use std::sync::Arc;
use tower_http::trace::TraceLayer;

#[tokio::main]
async fn main() {
    // 初始化日志
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    // 初始化 SQLite 数据库
    let db_path = std::env::var("DB_PATH")
        .unwrap_or_else(|_| "licenses.db".to_string());
    let pool = db::init_pool(&db_path).await.expect("DB 初始化失败");
    let pool = Arc::new(pool);

    // 管理员 Token（从环境变量读取）
    let admin_token = std::env::var("ADMIN_TOKEN")
        .expect("请设置 ADMIN_TOKEN 环境变量");
    let admin_token = Arc::new(admin_token);

    // 路由配置
    let app = Router::new()
        .route("/activate", post(handlers::activate))
        .route("/verify",   post(handlers::verify))
        .route("/health",   get(handlers::health))
        .route("/admin/licenses", get(handlers::list_licenses))
        .route("/admin/revoke",   delete(handlers::revoke_license))
        .route("/admin/extend",   post(handlers::extend_license))
        .layer(Extension(pool))
        .layer(Extension(admin_token))
        .layer(TraceLayer::new_for_http());

    let bind_addr = std::env::var("BIND_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8080".to_string());

    // ✅ 修复2: tracing::info 是宏，必须加 ! 才能调用
    // ❌ 错误原写法: tracing::info("License Server 启动于 {}", bind_addr);
    tracing::info!("License Server 启动于 {}", bind_addr);

    let listener = tokio::net::TcpListener::bind(&bind_addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}