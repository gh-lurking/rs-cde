// server/src/db.rs — 优化版 v8
//
// ✅ OPT-1 FIX: batch_init_keys 使用 unnest() 批量 INSERT
// ✅ OPT-5 FIX: expires_at 部分索引（WHERE revoked=FALSE AND activation_ts>0）
// ✅ LOGIC-A: extend_license 使用 GREATEST(expires_at, now) + extra_secs

use serde::{Deserialize, Serialize};
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
        &uid[16..20]
    )
}

fn hash_key(key: &str) -> String {
    use sha2::{Digest, Sha256};
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
            key          TEXT NOT NULL,
            key_hash     TEXT PRIMARY KEY,
            activation_ts BIGINT NOT NULL DEFAULT 0,
            expires_at   BIGINT NOT NULL DEFAULT 0,
            revoked      BOOLEAN NOT NULL DEFAULT FALSE,
            created_at   BIGINT NOT NULL,
            last_check   BIGINT,
            note         TEXT NOT NULL DEFAULT ''
        )",
    )
    .execute(&pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_licenses_key_hash ON licenses (key_hash)")
        .execute(&pool)
        .await?;

    // ✅ OPT-5 FIX: 部分索引，仅覆盖有效且已激活的 key
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_licenses_active_expires
         ON licenses (expires_at)
         WHERE revoked = FALSE AND activation_ts > 0",
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

pub async fn insert_license(
    pool: &DbPool,
    key: &str,
    key_hash: &str,
    created_at: i64,
    note: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO licenses (key, key_hash, created_at, note)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (key_hash) DO NOTHING",
    )
    .bind(key)
    .bind(key_hash)
    .bind(created_at)
    .bind(note)
    .execute(pool)
    .await?;
    Ok(())
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

/// ✅ LOGIC-A: GREATEST(expires_at, now) + extra_secs
/// 已过期的 key 从当前时间续期；未过期的从原到期时间续期
pub async fn extend_license(
    pool: &DbPool,
    key_hash: &str,
    extra_secs: i64,
) -> Result<Option<i64>, sqlx::Error> {
    let now = now_db();
    // 最大续期 10年
    let extra_secs = extra_secs.min(315_360_000);
    let row: Option<(i64,)> = sqlx::query_as(
        "UPDATE licenses
         SET expires_at = GREATEST(expires_at, $1) + $2
         WHERE key_hash = $3
           AND revoked = FALSE
           AND activation_ts > 0  -- 未激活的 key 不允许续期
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

/// ✅ OPT-1 FIX: 使用 unnest() 批量 INSERT，O(1) DB trips
pub async fn batch_init_keys(
    pool: &DbPool,
    keys: &[String],
    note: &str,
) -> Result<(), sqlx::Error> {
    if keys.is_empty() {
        return Ok(());
    }
    let now = now_db();
    let key_hashes: Vec<String> = keys.iter().map(|k| hash_key(k)).collect();
    let created_ats = vec![now; keys.len()];
    let notes = vec![note.to_string(); keys.len()];

    sqlx::query(
        "INSERT INTO licenses (key, key_hash, created_at, note)
         SELECT * FROM UNNEST($1::text[], $2::text[], $3::bigint[], $4::text[])
         ON CONFLICT (key_hash) DO NOTHING",
    )
    .bind(keys)
    .bind(&key_hashes)
    .bind(&created_ats)
    .bind(&notes)
    .execute(pool)
    .await?;

    tracing::info!("[DB] batch_init_keys: {} keys inserted", keys.len());
    Ok(())
}
