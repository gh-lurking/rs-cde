// server/src/db.rs — 优化版 v5
// ✅ MINOR-1 FIX: extend_license SQL 加 AND activation_ts > 0（未激活密钥不允许延期）
// ✅ MINOR-2 FIX: batch_init_keys 返回 (rows_affected, Vec<String>) 包含 key 列表
use hex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

pub type DbPool = PgPool;

fn now_db() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn generate_hkey() -> String {
    let uid = Uuid::new_v4().simple().to_string().to_uppercase();
    format!(
        "{}-{}-{}-{}-{}",
        &uid[12..16],
        &uid[0..4],
        &uid[4..8],
        &uid[8..12],
        &uid[16..20],
    )
}

fn hash_key(key: &str) -> String {
    let mut h = Sha256::new();
    h.update(key.as_bytes());
    hex::encode(h.finalize())
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct LicenseRecord {
    pub key: String,
    pub key_hash: String,
    pub activation_ts: i64,
    pub expires_at: i64,
    pub revoked: bool,
    pub created_at: i64,
    pub last_check: Option<i64>,
    pub note: String,
}

pub async fn init_pool(database_url: &str) -> Result<DbPool, sqlx::Error> {
    let max_conn: u32 = std::env::var("PG_POOL_MAX_CONN")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(20);
    let min_conn: u32 = std::env::var("PG_POOL_MIN_CONN")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2);
    let pool = PgPoolOptions::new()
        .max_connections(max_conn)
        .min_connections(min_conn)
        .acquire_timeout(Duration::from_secs(5))
        .idle_timeout(Duration::from_secs(600))
        .max_lifetime(Duration::from_secs(1800))
        .connect(database_url)
        .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS licenses (
            key TEXT NOT NULL,
            key_hash TEXT PRIMARY KEY,
            activation_ts BIGINT NOT NULL DEFAULT 0,
            expires_at BIGINT NOT NULL DEFAULT 0,
            revoked BOOLEAN NOT NULL DEFAULT FALSE,
            created_at BIGINT NOT NULL,
            last_check BIGINT,
            note TEXT NOT NULL DEFAULT ''
        )",
    )
    .execute(&pool)
    .await?;
    tracing::info!(
        "PostgreSQL pool ready: max={} min={} acquire=5s idle=600s lifetime=1800s",
        max_conn,
        min_conn
    );
    Ok(pool)
}

pub async fn find_license(
    pool: &DbPool,
    key_hash: &str,
) -> Result<Option<LicenseRecord>, sqlx::Error> {
    sqlx::query_as::<_, LicenseRecord>(
        "SELECT key, key_hash, activation_ts, expires_at, revoked, created_at, last_check, note
         FROM licenses WHERE key_hash = $1",
    )
    .bind(key_hash)
    .fetch_optional(pool)
    .await
}

pub async fn activate_license(
    pool: &DbPool,
    key_hash: &str,
    activation_ts: i64,
    expires_at: i64,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE licenses SET activation_ts = $1, expires_at = $2
         WHERE key_hash = $3 AND activation_ts = 0 AND revoked = FALSE",
    )
    .bind(activation_ts)
    .bind(expires_at)
    .bind(key_hash)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
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

/// ✅ MINOR-1 FIX: 加 AND activation_ts > 0，未激活密钥不允许被延期
/// 返回 Option<i64>: Some(new_expires_at) = 延期成功, None = 未找到/未激活/已 revoke
pub async fn extend_license(
    pool: &DbPool,
    key_hash: &str,
    extra_secs: i64,
) -> Result<Option<i64>, sqlx::Error> {
    let now = now_db();
    let row: Option<(i64,)> = sqlx::query_as(
        "UPDATE licenses
         SET expires_at = GREATEST(expires_at, $1) + $2
         WHERE key_hash = $3
           AND revoked = FALSE
           AND activation_ts > 0  -- ✅ MINOR-1 FIX: 未激活密钥不允许延期
         RETURNING expires_at",
    )
    .bind(now)
    .bind(extra_secs)
    .bind(key_hash)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| r.0))
}

pub async fn list_all_licenses(pool: &DbPool) -> Result<Vec<LicenseRecord>, sqlx::Error> {
    sqlx::query_as::<_, LicenseRecord>(
        "SELECT key, key_hash, activation_ts, expires_at, revoked, created_at, last_check, note
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
    let now = now_db();
    let result = sqlx::query(
        "INSERT INTO licenses (key, key_hash, activation_ts, expires_at, revoked, created_at, last_check, note)
         VALUES ($1, $2, 0, $3, FALSE, $4, NULL, $5)
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

/// ✅ MINOR-2 FIX: 返回 (rows_affected, Vec<String>) 包含实际生成的 key 列表
/// 避免网络超时后无法获取已创建的 key
pub async fn batch_init_keys(
    pool: &DbPool,
    count: u32,
    expires_at: i64,
    note: &str,
) -> Result<(u64, Vec<String>), sqlx::Error> {
    let now = now_db();
    let mut keys = Vec::with_capacity(count as usize);
    let mut rows_affected = 0u64;
    for _ in 0..count {
        let hkey = generate_hkey();
        let key_hash = hash_key(&hkey);
        let result = sqlx::query(
            "INSERT INTO licenses (key, key_hash, activation_ts, expires_at, revoked, created_at, last_check, note)
             VALUES ($1, $2, 0, $3, FALSE, $4, NULL, $5)
             ON CONFLICT (key_hash) DO NOTHING",
        )
        .bind(&hkey)
        .bind(&key_hash)
        .bind(expires_at)
        .bind(now)
        .bind(note)
        .execute(pool)
        .await?;
        if result.rows_affected() == 1 {
            rows_affected += 1;
            keys.push(hkey);
        }
    }
    Ok((rows_affected, keys))
}
