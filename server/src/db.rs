// server/src/db.rs — SQLite 数据访问层（sqlx 0.7）
// ✅ 修复3: 去掉未使用的 Row 导入（原 use sqlx::{SqlitePool, Row}）
// ❌ 原写法: use sqlx::{SqlitePool, Row};  // Row 未使用 → 警告
use sqlx::SqlitePool;
use serde::{Deserialize, Serialize};

pub type DbPool = SqlitePool;

// ✅ 修复4: 所有时间戳字段从 u64 改为 i64
// SQLite INTEGER 类型在 sqlx 中只映射到 i64，u64 不实现
// sqlx::Decode<'_, Sqlite> 和 sqlx::Type<Sqlite>
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct LicenseRecord {
    pub key_hash:      String,   // SHA256(HKEY) hex，不存明文
    // ❌ 原写法: pub activation_ts: u64,  // E0277: u64 不实现 sqlx::Decode
    pub activation_ts: i64,     // ✅ 用 i64，对外 API 再 as u64 转换
    pub expires_at:    i64,     // ✅ 同上，Unix 时间戳在 2^63 内不会溢出
    pub revoked:       bool,    // bool 可正常映射 SQLite BOOLEAN
    pub created_at:    i64,     // ✅ 同上
    pub note:          String,  // 管理员备注
}

/// 创建连接池 + 建表
pub async fn init_pool(db_path: &str) -> Result<DbPool, sqlx::Error> {
    let url = format!("sqlite://{}?mode=rwc", db_path);
    let pool = SqlitePool::connect(&url).await?;

    sqlx::query("
        CREATE TABLE IF NOT EXISTS licenses (
            key_hash      TEXT    PRIMARY KEY,
            activation_ts INTEGER NOT NULL,
            expires_at    INTEGER NOT NULL,
            revoked       BOOLEAN NOT NULL DEFAULT 0,
            created_at    INTEGER NOT NULL,
            last_check    INTEGER,
            note          TEXT    DEFAULT ''
        )
    ").execute(&pool).await?;

    Ok(pool)
}

pub async fn find_license(
    pool: &DbPool,
    key_hash: &str,
) -> Result<Option<LicenseRecord>, sqlx::Error> {
    // ✅ 修复后：LicenseRecord 字段全为 i64，FromRow 能正确推导
    sqlx::query_as::<_, LicenseRecord>(
        "SELECT key_hash, activation_ts, expires_at, revoked, created_at, note
         FROM licenses WHERE key_hash = ?"
    )
    .bind(key_hash)
    .fetch_optional(pool).await
}

pub async fn insert_license(
    pool: &DbPool,
    r: &LicenseRecord,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT OR IGNORE INTO licenses
         (key_hash, activation_ts, expires_at, revoked, created_at, note)
         VALUES (?, ?, ?, ?, ?, ?)"
    )
    .bind(&r.key_hash)
    // ✅ 字段已是 i64，直接 bind 无需 as i64 强转
    .bind(r.activation_ts)
    .bind(r.expires_at)
    .bind(r.revoked)
    .bind(r.created_at)
    .bind(&r.note)
    .execute(pool).await?;
    Ok(())
}

pub async fn update_last_check(
    pool: &DbPool,
    key_hash: &str,
    ts: i64,  // ✅ 参数也改为 i64
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE licenses SET last_check = ? WHERE key_hash = ?")
        .bind(ts)
        .bind(key_hash)
        .execute(pool).await?;
    Ok(())
}

pub async fn revoke_license(
    pool: &DbPool,
    key_hash: &str,
    reason: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE licenses SET revoked = 1, note = ? WHERE key_hash = ?")
        .bind(reason)
        .bind(key_hash)
        .execute(pool).await?;
    Ok(())
}

pub async fn extend_license(
    pool: &DbPool,
    key_hash: &str,
    extra_secs: i64,  // ✅ 参数也改为 i64
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE licenses SET expires_at = expires_at + ? WHERE key_hash = ?"
    )
    .bind(extra_secs)
    .bind(key_hash)
    .execute(pool).await?;
    Ok(())
}

pub async fn list_all_licenses(
    pool: &DbPool,
) -> Result<Vec<LicenseRecord>, sqlx::Error> {
    sqlx::query_as::<_, LicenseRecord>(
        "SELECT key_hash, activation_ts, expires_at, revoked, created_at, note
         FROM licenses ORDER BY created_at DESC"
    )
    .fetch_all(pool).await
}