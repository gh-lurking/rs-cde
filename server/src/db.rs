// server/src/db.rs — 优化版 v3
//
// [OPT-4 FIX] now_db() 防 panic + 防溢出
// [OPT-5 FIX] batch_init_keys 分批执行（每批 2000 条），明确 PG 参数上限注释
// [NEW-EXP-1] 新增 start_expired_cleanup_task() 周期性清理过期密钥
// [NEW-EXP-2] 新增 clean_expired_licenses() 清理方法

use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub type DbPool = PgPool;

pub const MAX_EXTEND_DAYS: i64 = 3650;
pub const MAX_EXTEND_SECS: i64 = MAX_EXTEND_DAYS * 86400;

// PG 协议参数上限为 65535（$1..$65535）
// 当前 INSERT 有 4 列，每批 2000 条 = 8000 参数，安全余量充足
const BATCH_SIZE: usize = 2_000;

// [NEW-EXP-1] 过期清理配置
const EXPIRED_CLEANUP_RETENTION_DAYS: i64 = 90; // 保留 90 天内过期的记录
const EXPIRED_CLEANUP_INTERVAL_HOURS: u64 = 6;

// [OPT-4] 防 panic（时钟早于 UNIX_EPOCH）+ 防溢出（u64 as i64 截断）
fn now_db() -> i64 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    i64::try_from(secs).unwrap_or(i64::MAX)
}

pub fn hash_key(key: &str) -> String {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
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

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_licenses_key_hash ON licenses (key_hash)")
        .execute(&pool)
        .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_licenses_active_expires ON licenses (expires_at)
         WHERE revoked = FALSE AND activation_ts > 0",
    )
    .execute(&pool)
    .await?;

    tracing::info!("PostgreSQL pool ready: max={} min={}", max_conn, min_conn);
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

pub async fn get_key_only(pool: &DbPool, key_hash: &str) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar("SELECT key FROM licenses WHERE key_hash = $1")
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
    let r = sqlx::query(
        "UPDATE licenses
         SET activation_ts = $1, expires_at = $2
         WHERE key_hash = $3 AND activation_ts = 0 AND revoked = FALSE",
    )
    .bind(activation_ts)
    .bind(expires_at)
    .bind(key_hash)
    .execute(pool)
    .await?;
    Ok(r.rows_affected() == 1)
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
) -> Result<bool, sqlx::Error> {
    let r = sqlx::query("UPDATE licenses SET revoked = TRUE, note = $1 WHERE key_hash = $2")
        .bind(reason)
        .bind(key_hash)
        .execute(pool)
        .await?;
    Ok(r.rows_affected() > 0)
}

pub async fn extend_license(
    pool: &DbPool,
    key_hash: &str,
    extra_secs: i64,
    allow_expired: bool,
) -> Result<Option<i64>, sqlx::Error> {
    let now = now_db();
    let extra_secs = extra_secs.clamp(1, MAX_EXTEND_SECS);

    if allow_expired {
        sqlx::query_scalar::<_, i64>(
            "UPDATE licenses
             SET expires_at = GREATEST(expires_at, $1) + $2
             WHERE key_hash = $3 AND revoked = FALSE AND activation_ts > 0
             RETURNING expires_at",
        )
        .bind(now)
        .bind(extra_secs)
        .bind(key_hash)
        .fetch_optional(pool)
        .await
    } else {
        sqlx::query_scalar::<_, i64>(
            "UPDATE licenses
             SET expires_at = expires_at + $2
             WHERE key_hash = $3 AND revoked = FALSE AND activation_ts > 0 AND expires_at > $1
             RETURNING expires_at",
        )
        .bind(now)
        .bind(extra_secs)
        .bind(key_hash)
        .fetch_optional(pool)
        .await
    }
}

pub async fn list_all_licenses(pool: &DbPool) -> Result<Vec<LicenseRecord>, sqlx::Error> {
    sqlx::query_as::<_, LicenseRecord>(
        "SELECT key, key_hash, activation_ts, expires_at, revoked, created_at, last_check, note
         FROM licenses ORDER BY created_at DESC LIMIT 10000",
    )
    .fetch_all(pool)
    .await
}

// [OPT-5] 分批插入，每批 BATCH_SIZE=2000 条
pub async fn batch_init_keys(
    pool: &DbPool,
    keys: &[String],
    note: &str,
) -> Result<(), sqlx::Error> {
    if keys.is_empty() {
        return Ok(());
    }

    let now = now_db();
    for chunk in keys.chunks(BATCH_SIZE) {
        let key_hashes: Vec<String> = chunk.iter().map(|k| hash_key(k)).collect();
        let created_ats = vec![now; chunk.len()];
        let notes = vec![note.to_string(); chunk.len()];

        sqlx::query(
            "INSERT INTO licenses (key, key_hash, created_at, note)
             SELECT * FROM UNNEST($1::text[], $2::text[], $3::bigint[], $4::text[])
             ON CONFLICT (key_hash) DO NOTHING",
        )
        .bind(chunk)
        .bind(&key_hashes)
        .bind(&created_ats)
        .bind(&notes)
        .execute(pool)
        .await?;
    }

    tracing::info!("[DB] batch_init_keys: {} keys inserted", keys.len());
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// [NEW-EXP-1] 过期密钥清理任务
// 与 CLAUDE.md §2「Simplicity First」一致：最小实现，不引入外部任务调度
// 默认每 6 小时执行，清理超过 90 天前过期的已撤销或未激活密钥
// 通过环境变量控制：
//   EXPIRED_CLEANUP_RETENTION_DAYS: 保留天数（默认 90）
//   EXPIRED_CLEANUP_INTERVAL_HOURS: 执行间隔小时（默认 6）
//   设为 0 可完全禁用清理
// ═══════════════════════════════════════════════════════════════════════════════

pub fn start_expired_cleanup_task(pool: Arc<DbPool>) {
    let interval_hours: u64 = std::env::var("EXPIRED_CLEANUP_INTERVAL_HOURS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(EXPIRED_CLEANUP_INTERVAL_HOURS);

    if interval_hours == 0 {
        tracing::info!("[DB] expired cleanup disabled (interval=0)");
        return;
    }

    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(interval_hours * 3600)).await;
            match clean_expired_licenses(&pool).await {
                Ok(count) if count > 0 => {
                    tracing::info!("[DB] expired cleanup: removed {} records", count);
                }
                Ok(_) => {} // 无过期记录
                Err(e) => {
                    tracing::warn!("[DB] expired cleanup failed: {}", e);
                }
            }
        }
    });

    tracing::info!(
        "[DB] expired cleanup task started (interval={}h)",
        interval_hours
    );
}

/// 清理策略：
/// 1. 已撤销且过期超过 retention_days 的记录
/// 2. 已激活且过期超过 retention_days 的记录（保留数据以供审计）
async fn clean_expired_licenses(pool: &DbPool) -> Result<u64, sqlx::Error> {
    let retention_days: i64 = std::env::var("EXPIRED_CLEANUP_RETENTION_DAYS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(EXPIRED_CLEANUP_RETENTION_DAYS);

    let cutoff = now_db() - retention_days * 86400;

    // 只清理已撤销的长期过期记录（保留未撤销的记录用于审计和历史查询）
    let result = sqlx::query(
        "DELETE FROM licenses
         WHERE revoked = TRUE
           AND activation_ts > 0
           AND expires_at < $1
           AND expires_at > 0",
    )
    .bind(cutoff)
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}
