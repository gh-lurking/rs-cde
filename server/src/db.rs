// server/src/db.rs — PostgreSQL 数据访问层（sqlx 0.7）
//
// ✅ 变更1: DbPool 从 SqlitePool 改为 PgPool
// ✅ 变更2: LicenseRecord 新增 key 明文字段（同时存储明文 + key_hash）
// ✅ 变更3: init_pool() 从 sqlite:// 连接串改为 postgres:// 连接串
// ✅ 变更4: SQL 语法适配 PostgreSQL（? → $N 占位符，BOOLEAN → BOOL）
// ✅ 变更5: 新增 add_key() 函数，供 /admin/add-key 接口调用
// ✅ 变更6: 新增 batch_init() 函数，供 /admin/batch-init 接口调用

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

pub type DbPool = PgPool;

// ─────────────────────────────────────────────────────────────────────────────
// 数据模型
// ─────────────────────────────────────────────────────────────────────────────

/// License 记录（对应 licenses 表一行）
///
/// ✅ 变更2: 新增 key 字段存储明文秘钥
///   - key      : 明文，如 "HKEY-AAAA-1111-XXXX"（管理员分发给用户的字符串）
///   - key_hash : SHA256(key) hex，客户端上报、数据库索引字段
///
/// 两者都存入 DB，方便管理员查阅原始 key 同时保持 hash 索引效率。
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct LicenseRecord {
    /// 明文秘钥（仅服务端可见，不下发给客户端）
    pub key: String,
    /// SHA256(key) hex，客户端只上报此值
    pub key_hash: String,
    /// 首次激活 Unix 时间戳（秒）
    pub activation_ts: i64,
    /// 过期 Unix 时间戳（秒）
    pub expires_at: i64,
    /// 是否已吊销
    pub revoked: bool,
    /// 记录创建时间戳
    pub created_at: i64,
    /// 管理员备注
    pub note: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// 连接池初始化
// ─────────────────────────────────────────────────────────────────────────────

/// 创建 PostgreSQL 连接池并初始化表结构
///
/// ✅ 变更3: 环境变量 DATABASE_URL 格式为
///   postgres://user:password@host:5432/dbname
pub async fn init_pool(database_url: &str) -> Result<DbPool, sqlx::Error> {
    let pool = PgPool::connect(database_url).await?;

    // ✅ 变更4: PostgreSQL 语法
    //   - BOOLEAN  (SQLite 用 BOOLEAN NOT NULL DEFAULT 0 → PG 用 BOOLEAN NOT NULL DEFAULT FALSE)
    //   - TEXT PRIMARY KEY 在 PG 中保持不变
    //   - INTEGER  → BIGINT（对应 i64）
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS licenses (
            key           TEXT        NOT NULL,
            key_hash      TEXT        PRIMARY KEY,
            activation_ts BIGINT      NOT NULL DEFAULT 0,
            expires_at    BIGINT      NOT NULL,
            revoked       BOOLEAN     NOT NULL DEFAULT FALSE,
            created_at    BIGINT      NOT NULL,
            last_check    BIGINT,
            note          TEXT        NOT NULL DEFAULT ''
        )",
    )
    .execute(&pool)
    .await?;

    Ok(pool)
}

// ─────────────────────────────────────────────────────────────────────────────
// 查询 / 写入
// ─────────────────────────────────────────────────────────────────────────────

/// 按 key_hash 查找 License 记录
pub async fn find_license(
    pool: &DbPool,
    key_hash: &str,
) -> Result<Option<LicenseRecord>, sqlx::Error> {
    // ✅ 变更4: PostgreSQL 占位符为 $1, $2, ...（SQLite 用 ?）
    sqlx::query_as::<_, LicenseRecord>(
        "SELECT key, key_hash, activation_ts, expires_at, revoked, created_at, last_check, note
         FROM licenses WHERE key_hash = $1",
    )
    .bind(key_hash)
    .fetch_optional(pool)
    .await
}

/// 激活时写入新 License 记录（key_hash 冲突时忽略，保证幂等）
pub async fn insert_license(pool: &DbPool, r: &LicenseRecord) -> Result<(), sqlx::Error> {
    // ✅ 变更4: PostgreSQL 用 ON CONFLICT DO NOTHING
    //           SQLite 用的是 INSERT OR IGNORE
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

/// 更新最后一次在线校验时间戳
pub async fn update_last_check(pool: &DbPool, key_hash: &str, ts: i64) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE licenses SET last_check = $1 WHERE key_hash = $2")
        .bind(ts)
        .bind(key_hash)
        .execute(pool)
        .await?;
    Ok(())
}

/// 吊销 License
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

/// 延长 License 有效期
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

/// 查询所有 License 记录（管理员列表）
pub async fn list_all_licenses(pool: &DbPool) -> Result<Vec<LicenseRecord>, sqlx::Error> {
    sqlx::query_as::<_, LicenseRecord>(
        "SELECT key, key_hash, activation_ts, expires_at, revoked, created_at, note
         FROM licenses ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await
}

// ─────────────────────────────────────────────────────────────────────────────
// ✅ 变更5: 新增 add_key() — 预置 License Key（服务端批量初始化入口）
// ─────────────────────────────────────────────────────────────────────────────

/// 向数据库预置一条未激活的 License（key 明文 + key_hash + 有效期）。
///
/// 若 key_hash 已存在则忽略（ON CONFLICT DO NOTHING），保证幂等。
/// activation_ts = 0 表示尚未被任何客户端首次激活。
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

    // rows_affected == 1 表示真正插入；== 0 表示 key_hash 已存在被忽略
    Ok(result.rows_affected() == 1)
}

/// 批量生成 License Key 并入库（系统初始化用）
///
/// - activation_ts 默认值 0（未激活）
/// - expires_at 默认值 0（未激活不过期）
/// - created_at 为生成时间
/// - last_check 默认值 0
/// - note 字段默认 "系统初始化生成"
pub async fn batch_init_keys(pool: &DbPool, count: u32, note: &str) -> Result<u64, sqlx::Error> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let mut inserted: u64 = 0;
    for _ in 0..count {
        // 生成格式为 HKEY-XXXX-XXXX-XXXX 的随机秘钥
        let uid = Uuid::new_v4().simple().to_string().to_uppercase();
        let key = format!("{}-{}-{}-{}", &uid[12..16],  &uid[0..4], &uid[4..8], &uid[8..12]);
        let key_hash = {
            let mut h = Sha256::new();
            h.update(key.as_bytes());
            hex::encode(h.finalize())
        };

        let result = sqlx::query(
            "INSERT INTO licenses
                (key, key_hash, activation_ts, expires_at,
                 revoked, created_at, last_check, note)
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
