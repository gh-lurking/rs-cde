// server/src/db.rs — PostgreSQL 数据访问层（sqlx 0.7）
//
// ✅ 变更: init_pool() 精细化 PgPoolOptions 连接池参数
//
// 连接池参数说明：
// | 参数             | 默认值 | 环境变量          | 说明                          |
// |------------------|--------|-------------------|-------------------------------|
// | max_connections  |   20   | PG_POOL_MAX_CONN  | 最大连接数                    |
// | min_connections  |    2   | PG_POOL_MIN_CONN  | 最小保活连接（减冷启动延迟）  |
// | acquire_timeout  |    5s  | —                 | 等待空闲连接的最长时间        |
// | idle_timeout     |  600s  | —                 | 空闲连接超时回收（10 min）    |
// | max_lifetime     | 1800s  | —                 | 单连接最长生存时间（30 min）  |

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::time::Duration;
use uuid::Uuid;

pub type DbPool = PgPool;

// ── 数据模型 ──────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct LicenseRecord {
    pub key: String,
    pub key_hash: String,
    pub activation_ts: i64,
    pub expires_at: i64,
    pub revoked: bool,
    pub created_at: i64,
    pub note: String,
}

// ── 连接池初始化（精细化参数）─────────────────────────────────────────────

pub async fn init_pool(database_url: &str) -> Result<DbPool, sqlx::Error> {
    let max_conn: u32 = std::env::var("PG_POOL_MAX_CONN")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(20);

    let min_conn: u32 = std::env::var("PG_POOL_MIN_CONN")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2);

    // ✅ 精细化连接池配置
    let pool = PgPoolOptions::new()
        .max_connections(max_conn)
        .min_connections(min_conn)
        .acquire_timeout(Duration::from_secs(5))
        .idle_timeout(Duration::from_secs(600))
        .max_lifetime(Duration::from_secs(1800))
        .connect(database_url)
        .await?;

    // 建表（幂等）
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS licenses (
            key           TEXT    NOT NULL,
            key_hash      TEXT    PRIMARY KEY,
            activation_ts BIGINT  NOT NULL DEFAULT 0,
            expires_at    BIGINT  NOT NULL,
            revoked       BOOLEAN NOT NULL DEFAULT FALSE,
            created_at    BIGINT  NOT NULL,
            last_check    BIGINT,
            note          TEXT    NOT NULL DEFAULT ''
        )",
    )
    .execute(&pool)
    .await?;

    tracing::info!(
        "PostgreSQL connection pool: max={} min={} acquire=5s idle=600s lifetime=1800s",
        max_conn,
        min_conn
    );

    Ok(pool)
}

// ── 查询 / 写入（与原版完全相同）─────────────────────────────────────────
pub async fn find_license(
    pool: &DbPool,
    key_hash: &str,
) -> Result<Option<LicenseRecord>, sqlx::Error> {
    sqlx::query_as::<_, LicenseRecord>(
        "SELECT key, key_hash, activation_ts, expires_at,
                revoked, created_at, note
           FROM licenses WHERE key_hash = $1",
    )
    .bind(key_hash)
    .fetch_optional(pool)
    .await
}

pub async fn insert_license(pool: &DbPool, r: &LicenseRecord) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO licenses
            (key, key_hash, activation_ts, expires_at, revoked, created_at, note)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (key_hash) DO NOTHING",
    )
    .bind(&r.key)
    .bind(&r.key_hash)
    .bind(r.activation_ts)
    .bind(r.expires_at)
    .bind(r.revoked)
    .bind(r.created_at)
    .bind(&r.note)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn update_last_check(pool: &DbPool, key_hash: &str, ts: i64) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE licenses SET last_check = $1 WHERE key_hash = $2")
        .bind(ts)
        .bind(key_hash)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn revoke_license(
    pool: &DbPool,
    key_hash: &str,
    reason: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE licenses SET revoked = TRUE, note = $1 WHERE key_hash = $2")
        .bind(reason)
        .bind(key_hash)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn extend_license(
    pool: &DbPool,
    key_hash: &str,
    extra_secs: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE licenses SET expires_at = expires_at + $1 WHERE key_hash = $2")
        .bind(extra_secs)
        .bind(key_hash)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn list_all_licenses(pool: &DbPool) -> Result<Vec<LicenseRecord>, sqlx::Error> {
    sqlx::query_as::<_, LicenseRecord>(
        "SELECT key, key_hash, activation_ts, expires_at,
                revoked, created_at, note
           FROM licenses ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await
}

pub async fn add_key(
    pool: &DbPool,
    key: &str,
    key_hash: &str,
    expires_at: i64,
    note: &str,
) -> Result<bool, sqlx::Error> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let result = sqlx::query(
        "INSERT INTO licenses
            (key, key_hash, activation_ts, expires_at, revoked, created_at, note)
         VALUES ($1, $2, 0, $3, FALSE, $4, $5)
         ON CONFLICT (key_hash) DO NOTHING",
    )
    .bind(key)
    .bind(key_hash)
    .bind(expires_at)
    .bind(now)
    .bind(note)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() == 1)
}

pub async fn batch_init_keys(pool: &DbPool, count: u32, note: &str) -> Result<u64, sqlx::Error> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let mut inserted: u64 = 0;

    for _ in 0..count {
        let uid = Uuid::new_v4().simple().to_string().to_uppercase();
        let key = format!(
            "{}-{}-{}-{}",
            &uid[12..16],
            &uid[0..4],
            &uid[4..8],
            &uid[8..12],
        );
        let key_hash = {
            let mut h = Sha256::new();
            h.update(key.as_bytes());
            hex::encode(h.finalize())
        };

        let result = sqlx::query(
            "INSERT INTO licenses
                (key, key_hash, activation_ts, expires_at, revoked, created_at, last_check, note)
             VALUES ($1, $2, 0, 0, FALSE, $3, 0, $4)
             ON CONFLICT (key_hash) DO NOTHING",
        )
        .bind(&key)
        .bind(&key_hash)
        .bind(now)
        .bind(note)
        .execute(pool)
        .await?;

        inserted += result.rows_affected();
    }

    Ok(inserted)
}
