// server/src/main.rs -- 优化版 v5
//
// MED-2 FIX : 启动 nonce_fallback::start_cleanup_task()
// OPT-1 FIX : 启动 cache::start_cache_cleanup_task()
// NEW       : 优雅关闭同时监听 SIGTERM（生产容器友好）
// [OPT-3] 新增 key_cache 模块声明

mod auth;
mod cache;
mod db;
mod handlers;
mod key_cache;
mod nonce_fallback; // [OPT-3] 进程内 key 映射缓存

use axum::{
    extract::DefaultBodyLimit,
    routing::{get, post},
    Extension, Router,
};
use std::sync::Arc;
use tower_http::trace::TraceLayer;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string()))
        .init();

    let database_url = std::env::var("DATABASE_URL").expect("Please set DATABASE_URL env");
    let pg_pool = db::init_pool(&database_url)
        .await
        .expect("PostgreSQL Connection Failure");
    let pg_pool = Arc::new(pg_pool);
    tracing::info!("PostgreSQL Connection Pool is ready");

    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379/0".to_string());
    let redis_pool = cache::init_redis_pool(&redis_url).expect("Redis Pool Init Failure");
    let redis_pool = Arc::new(redis_pool);
    tracing::info!("Redis Connection Pool is ready");

    let admin_token = std::env::var("ADMIN_TOKEN").expect("Please set ADMIN_TOKEN env");
    let admin_token = Arc::new(admin_token);

    // MED-2 FIX: 后台 cleanup 任务
    nonce_fallback::start_cleanup_task();
    // OPT-1 FIX: 启动 memory_revoke_map GC
    cache::start_cache_cleanup_task();
    // [NEW-EXP-1] 过期密钥周期性清理（默认每 6 小时）
    db::start_expired_cleanup_task(pg_pool.clone());

    let app = Router::new()
        .route("/activate", post(handlers::activate))
        .route("/verify", post(handlers::verify))
        .route("/health", get(handlers::health))
        .route("/admin/licenses", get(handlers::list_licenses))
        .route("/admin/revoke", post(handlers::revoke_license))
        .route("/admin/extend", post(handlers::extend_license))
        .route("/admin/add-key", post(handlers::add_key))
        .route("/admin/batch-init", post(handlers::batch_init))
        .layer(DefaultBodyLimit::max(65536))
        .layer(Extension(pg_pool))
        .layer(Extension(redis_pool))
        .layer(Extension(admin_token))
        .layer(TraceLayer::new_for_http());

    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    tracing::info!("Server running on {}", bind_addr);

    let listener = tokio::net::TcpListener::bind(&bind_addr).await.unwrap();

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}

// NEW: 同时监听 Ctrl-C 和 SIGTERM
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install CTRL+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("Graceful shutdown");
}
