// client/src/storage.rs — 优化版 v5
//
// [BUG-08 FIX] read_count 计算错误修正
// [OPT] HKDF 派生密钥（比直接 SHA256 截断更规范）
// [OPT] AES-128-GCM nonce 每次随机生成（OsRng），防止重放
// [OPT-2] 添加存储健康度监控
use aes_gcm::{
    aead::{Aead, OsRng},
    Aes128Gcm, Key, KeyInit, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::generic_array::GenericArray;

// 最大合理 License 期限：10 年
const MAX_LICENSE_PERIOD: u64 = 3650 * 86400;

// 存储健康度统计
static WRITE_SUCCESS_COUNT: AtomicUsize = AtomicUsize::new(0);
static WRITE_FAIL_COUNT: AtomicUsize = AtomicUsize::new(0);
static READ_SUCCESS_COUNT: AtomicUsize = AtomicUsize::new(0);
static READ_FAIL_COUNT: AtomicUsize = AtomicUsize::new(0);

pub fn get_storage_stats() -> (usize, usize, usize, usize) {
    (
        WRITE_SUCCESS_COUNT.load(Ordering::Relaxed),
        WRITE_FAIL_COUNT.load(Ordering::Relaxed),
        READ_SUCCESS_COUNT.load(Ordering::Relaxed),
        READ_FAIL_COUNT.load(Ordering::Relaxed),
    )
}

pub enum LocalReadResult {
    /// 读取到的有效副本不足
    Insufficient { read_count: usize },
    /// 副本被篡改（HMAC/解密失败或逻辑异常）
    Tampered { read_count: usize },
    /// 验证成功
    Success {
        value: (u64, u64), // (activation_ts, expires_at)
        read_count: usize,
        repair_failed: bool,
    },
}

/// HKDF 派生 AES-128-GCM 密钥
fn derive_key(hkey: &str, salt: &str) -> [u8; 16] {
    let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), hkey.as_bytes());
    let mut okm = [0u8; 16];
    hk.expand(b"aes-128-gcm-key", &mut okm)
        .expect("HKDF expand should never fail for 16-byte output");
    okm
}

/// 派生副本存储路径（slot 0/1/2 对应不同目录 + 文件名）
fn derive_path(hkey: &str, salt: &str, slot: u8) -> PathBuf {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(salt.as_bytes());
    h.update(hkey.as_bytes());
    let d = h.finalize();

    let dir_name = format!("{:02x}{:02x}{:02x}{:02x}", d[0], d[1], d[2], d[3]);
    let files = ["index.db", "cache.bin", "meta.dat"];

    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| "/tmp".to_string());

    let bases = [
        format!("{}/.cache/.sys/{}", home, dir_name),
        format!("{}/.local/share/.sys/{}", home, dir_name),
        format!("{}/.config/.sys/{}", home, dir_name),
    ];

    PathBuf::from(&bases[slot as usize % 3]).join(files[slot as usize % 3])
}

fn write_slot(
    path: &PathBuf,
    key_bytes: &[u8; 16],
    activation: u64,
    expires: u64,
) -> Result<(), String> {
    let key = Key::<Aes128Gcm>::from_slice(key_bytes);
    let cipher = Aes128Gcm::new(key);

    // 每次随机 nonce（OsRng），防止重放
    let nonce_bytes = Aes128Gcm::generate_key(&mut OsRng);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut plain = [0u8; 16];
    plain[..8].copy_from_slice(&activation.to_le_bytes());
    plain[8..].copy_from_slice(&expires.to_le_bytes());

    let ct = cipher
        .encrypt(nonce, plain.as_ref())
        .map_err(|e| format!("encrypt: {e}"))?;

    if let Some(p) = path.parent() {
        let _ = fs::create_dir_all(p);
    }

    // 格式: [12 字节 nonce] [16+16 字节 ciphertext+tag]
    let mut out = nonce_bytes.to_vec();
    out.extend_from_slice(&ct);

    fs::write(path, &out).map_err(|e| format!("write: {e}"))?;

    WRITE_SUCCESS_COUNT.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

fn read_slot(path: &PathBuf, key_bytes: &[u8; 16]) -> Option<(u64, u64)> {
    let data = fs::read(path).ok()?;

    // 数据长度校验
    if data.len() != 44 {
        // 12(nonce) + 16(plain) + 16(tag) = 44
        READ_FAIL_COUNT.fetch_add(1, Ordering::Relaxed);
        return None;
    }

    let key = Key::<Aes128Gcm>::from_slice(key_bytes);
    let cipher = Aes128Gcm::new(key);
    let nonce = Nonce::from_slice(&data[..12]);

    let plain = cipher.decrypt(nonce, &data[12..]).ok()?;

    if plain.len() != 16 {
        READ_FAIL_COUNT.fetch_add(1, Ordering::Relaxed);
        return None;
    }

    let act = u64::from_le_bytes(plain[..8].try_into().unwrap());
    let exp = u64::from_le_bytes(plain[8..].try_into().unwrap());

    READ_SUCCESS_COUNT.fetch_add(1, Ordering::Relaxed);
    Some((act, exp))
}

/// 写入全部 3 个副本
pub fn write_all_replicas(hkey: &str, salt: &str, activation_ts: u64, expires_at: u64) {
    let key = derive_key(hkey, salt);
    for slot in 0..3u8 {
        let path = derive_path(hkey, salt, slot);
        if let Err(e) = write_slot(&path, &key, activation_ts, expires_at) {
            WRITE_FAIL_COUNT.fetch_add(1, Ordering::Relaxed);
            tracing::warn!("[Storage] 写入副本 {} 失败: {}", slot, e);
        }
    }
}

/// 合法性校验：防篡改 + 逻辑一致性
fn validate_and_return(val: (u64, u64), read_count: usize, repair_failed: bool) -> LocalReadResult {
    let now_u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let (act_ts, exp_ts) = val;

    // 1. activation_ts 在未来（防时钟回调攻击）
    if act_ts > now_u64 + 300 {
        return LocalReadResult::Tampered { read_count };
    }

    // 2. expires_at 为零或超出最大合理期限
    if exp_ts == 0 || exp_ts > now_u64 + MAX_LICENSE_PERIOD {
        return LocalReadResult::Tampered { read_count };
    }

    // 3. 激活时间 >= 过期时间（逻辑异常）
    if act_ts >= exp_ts {
        return LocalReadResult::Tampered { read_count };
    }

    LocalReadResult::Success {
        value: val,
        read_count,
        repair_failed,
    }
}

/// 读取本地 3 副本缓存，多数一致性投票
///
/// [BUG-08 FIX] 原代码 read_count 计算错误，修复后正确追踪读取成功数
pub fn read_local_record(hkey: &str, salt: &str) -> LocalReadResult {
    let key = derive_key(hkey, salt);
    let mut values: Vec<(u64, u64)> = Vec::with_capacity(3);

    for slot in 0..3u8 {
        let path = derive_path(hkey, salt, slot);
        if let Some(pair) = read_slot(&path, &key) {
            values.push(pair);
        }
    }

    let read_count = values.len();

    // [BUG-08 FIX] 至少需要 1 个有效副本
    if read_count == 0 {
        return LocalReadResult::Insufficient { read_count: 0 };
    }

    // 多数投票
    let mut counts: Vec<((u64, u64), usize)> = Vec::new();
    for &v in &values {
        if let Some(e) = counts.iter_mut().find(|(val, _)| *val == v) {
            e.1 += 1;
        } else {
            counts.push((v, 1));
        }
    }

    let (winner, winner_count) = counts.iter().max_by_key(|(_, c)| *c).copied().unwrap();

    // [BUG-08 FIX] majority_needed 动态调整
    // 1 个副本：需 1 票（只要能读出就接受）
    // 2+ 个副本：需 2 票（多数一致）
    let majority_needed = if read_count >= 2 { 2 } else { 1 };

    if winner_count >= majority_needed {
        // 一致性检查通过
        return validate_and_return(winner, read_count, false);
    }

    // 一致性检查失败：尝试自修复
    let mut failed = false;
    let mut repair_failed = false;

    for slot in 0..3u8 {
        let path = derive_path(hkey, salt, slot);
        let kb = derive_key(hkey, salt);
        match read_slot(&path, &kb) {
            Some(v) if v == winner => {
                // 已经一致，跳过
            }
            _ => {
                // 不一致，尝试修复
                if write_slot(&path, &kb, winner.0, winner.1).is_err() {
                    repair_failed = true;
                    failed = true;
                }
            }
        }
    }

    if failed && repair_failed {
        // 修复失败但部分成功，降级警告
        return validate_and_return(winner, read_count, true);
    }

    validate_and_return(winner, read_count, false)
}
