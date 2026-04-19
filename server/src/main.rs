// server/src/main.rs — 优化版 v3
//
// MED-2 FIX: 在 main() 中显式调用 nonce_fallback::start_cleanup_task()
// OPT-1 FIX: 在 main() 中显式调用 cache::start_cache_cleanup_task()

mod auth;
mod cache;
mod db;
mod handlers;
mod nonce_fallback;

use axum::{
    Extension, Router,
    extract::DefaultBodyLimit,
    routing::{get, post},
};
use std::sync::Arc;
use tower_http::trace::TraceLayer;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_env_filter("info").init();

    let database_url = std::env::var("DATABASE_URL").expect("Please set up the DATABASE_URL env");
    let pg_pool = db::init_pool(&database_url)
        .await
        .expect("PostgreSQL Connection Failure");
    let pg_pool = Arc::new(pg_pool);
    tracing::info!("PostgreSQL Connection Pool is ready");

    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379/0".to_string());
    let redis_pool =
        cache::init_redis_pool(&redis_url).expect("Redis Connection Pool Initialization Failure");
    let redis_pool = Arc::new(redis_pool);
    tracing::info!("Redis Connection Pool is ready (deadpool-redis)");

    let admin_token = std::env::var("ADMIN_TOKEN").expect("Please set up the ADMIN_TOKEN env");
    let admin_token = Arc::new(admin_token);

    // MED-2 FIX: 在 Tokio 运行时中显式启动 nonce cleanup 任务
    nonce_fallback::start_cleanup_task();
    // OPT-1 FIX: 启动 memory_revoke_map 的后台 GC
    cache::start_cache_cleanup_task();

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
    tracing::info!("Server is running on {}", bind_addr);
    let listener = tokio::net::TcpListener::bind(&bind_addr).await.unwrap();

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install CTRL+C handler");
    tracing::info!("Graceful shutdown");
}
