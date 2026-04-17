// server/src/main.rs — Axum Web 服务入口
//
// ✅ 变更1: 数据库从 SQLite 改为 PostgreSQL
//   - 环境变量从 DB_PATH 改为 DATABASE_URL
//   - DATABASE_URL 格式: postgres://user:password@host:5432/dbname
// ✅ 变更2: 新增路由 POST /admin/add-key → handlers::add_key

mod auth;
mod db;
mod handlers;

use axum::{
    Extension, Router,
    routing::{delete, get, post},
};
use std::sync::Arc;
use tower_http::trace::TraceLayer;

#[tokio::main]
async fn main() {
    // 初始化日志
    tracing_subscriber::fmt().with_env_filter("info").init();

    // ✅ 变更1: 读取 PostgreSQL 连接串
    // 示例: postgres://licenseuser:secret@localhost:5432/licensedb
    let database_url = std::env::var("DATABASE_URL")
        .expect("请设置 DATABASE_URL 环境变量，格式: postgres://user:pass@host:port/db");

    let pool = db::init_pool(&database_url)
        .await
        .expect("PostgreSQL 连接/初始化失败");
    let pool = Arc::new(pool);

    // 管理员 Token（从环境变量读取）
    let admin_token = std::env::var("ADMIN_TOKEN").expect("请设置 ADMIN_TOKEN 环境变量");
    let admin_token = Arc::new(admin_token);

    // 路由配置
    let app = Router::new()
        .route("/activate", post(handlers::activate))
        .route("/verify", post(handlers::verify))
        .route("/health", get(handlers::health))
        .route("/admin/licenses", get(handlers::list_licenses))
        .route("/admin/revoke", delete(handlers::revoke_license))
        .route("/admin/extend", post(handlers::extend_license))
        // ✅ 新增管理员预置 key 接口
        .route("/admin/add-key", post(handlers::add_key))
        .route("/admin/batch-init", post(handlers::batch_init))
        .layer(Extension(pool))
        .layer(Extension(admin_token))
        .layer(TraceLayer::new_for_http());

    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());

    tracing::info!("License Server (PostgreSQL) 启动于 {}", bind_addr);

    let listener = tokio::net::TcpListener::bind(&bind_addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
