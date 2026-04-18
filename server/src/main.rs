// server/src/main.rs — Axum Web 服务启动器

// ✅ 要点1：Redis 连接池初始化（deadpool-redis）
// ✅ 要点2：PostgreSQL 连接池初始化（op db.rs init_pool）
// ✅ 要点3：RedisPool 通过 Extension 同步传播

mod auth;
mod cache; // ✅ 初始化: Redis 缓存模块
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
    tracing_subscriber::fmt().with_env_filter("info").init();

    // ── PostgreSQL 连接池 ─────────────────────────────────────────────────────
    let database_url = std::env::var("DATABASE_URL").expect("请配置 DATABASE_URL 环境变量");

    // ✅ db::init_pool 已包含 PgPoolOptions（见 db.rs）
    let pg_pool = db::init_pool(&database_url)
        .await
        .expect("PostgreSQL 连接/建表失败");
    let pg_pool = Arc::new(pg_pool);
    tracing::info!("✅ PostgreSQL 连接池就绪");

    // ── Redis 连接池 ──────────────────────────────────────────────────────────
    // 格式: redis://[:password@]host:port[/db]
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379/0".to_string());

    let redis_pool = cache::init_redis_pool(&redis_url).expect("Redis 连接池初始化失败");
    let redis_pool = Arc::new(redis_pool);
    tracing::info!("✅ Redis 连接池就绪 (deadpool-redis)");

    let admin_token = std::env::var("ADMIN_TOKEN").expect("请配置 ADMIN_TOKEN 环境变量");
    let admin_token = Arc::new(admin_token);

    // ── 路由配置 ──────────────────────────────────────────────────────────────
    let app = Router::new()
        .route("/activate", post(handlers::activate))
        .route("/verify", post(handlers::verify))
        .route("/health", get(handlers::health))
        .route("/admin/licenses", get(handlers::list_licenses))
        .route("/admin/revoke", delete(handlers::revoke_license))
        .route("/admin/extend", post(handlers::extend_license))
        .route("/admin/add-key", post(handlers::add_key))
        .route("/admin/batch-init", post(handlers::batch_init))
        // ✅ 同时挂载 pg_pool 和 redis_pool
        .layer(Extension(pg_pool))
        .layer(Extension(redis_pool))
        .layer(Extension(admin_token))
        .layer(TraceLayer::new_for_http());

    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());

    tracing::info!("License Server 监听于 {}", bind_addr);
    let listener = tokio::net::TcpListener::bind(&bind_addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
