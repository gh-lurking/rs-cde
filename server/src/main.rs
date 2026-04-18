// server/src/main.rs — 无实质变化（路由结构正确）
mod auth;
mod cache;
mod db;
mod handlers;

use axum::{
    Extension, Router,
    routing::{get, post},
};
use std::sync::Arc;
use tower_http::trace::TraceLayer;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_env_filter("info").init();

    let database_url = std::env::var("DATABASE_URL").expect("请配置 DATABASE_URL 环境变量");
    let pg_pool = db::init_pool(&database_url)
        .await
        .expect("PostgreSQL 连接/建表失败");
    let pg_pool = Arc::new(pg_pool);
    tracing::info!("✅ PostgreSQL 连接池就绪");

    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379/0".to_string());
    let redis_pool = cache::init_redis_pool(&redis_url).expect("Redis 连接池初始化失败");
    let redis_pool = Arc::new(redis_pool);
    tracing::info!("✅ Redis 连接池就绪 (deadpool-redis)");

    let admin_token = std::env::var("ADMIN_TOKEN").expect("请配置 ADMIN_TOKEN 环境变量");
    let admin_token = Arc::new(admin_token);

    let app = Router::new()
        .route("/activate", post(handlers::activate))
        .route("/verify", post(handlers::verify))
        .route("/health", get(handlers::health))
        .route("/admin/licenses", get(handlers::list_licenses))
        .route("/admin/revoke", post(handlers::revoke_license))
        .route("/admin/extend", post(handlers::extend_license))
        .route("/admin/add-key", post(handlers::add_key))
        .route("/admin/batch-init", post(handlers::batch_init))
        .layer(Extension(pg_pool))
        .layer(Extension(redis_pool))
        .layer(Extension(admin_token))
        .layer(TraceLayer::new_for_http());

    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    tracing::info!("License Server 监听于 {}", bind_addr);
    let listener = tokio::net::TcpListener::bind(&bind_addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
