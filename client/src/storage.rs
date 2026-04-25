// client/src/storage.rs — 优化版 v3
//
// [BUG-S1 FIX] 投票 quorum 阈值：动态多数 (read_count/2)+1，而非固定 >= 2
// [BUG-S2 NOTE] validate_and_return 中 act_ts 零值检查已添加
// [BUG-01 FIX + C-01 FIX] act_ts == 0 / exp_ts == 0 提前拒绝
// [BUG-CRIT-2 FIX] 新增 LocalReadResult::Expired 变体，区分"过期"与"篡改"
// [BUG-CRIT-6 FIX] validate_and_return 使用 i64::try_from 安全转换 u64 → i64

use aes_gcm::{
    aead::{Aead, OsRng},
    AeadCore, Aes128Gcm, Key, KeyInit, Nonce,
};
use hkdf::Hkdf;
use sha2::Digest;
use sha2::Sha256;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_LICENSE_PERIOD: u64 = 10 * 365 * 86400;
static WRITE_SUCCESS_COUNT: AtomicU64 = AtomicU64::new(0);
static WRITE_FAIL_COUNT: AtomicU64 = AtomicU64::new(0);
static READ_SUCCESS_COUNT: AtomicU64 = AtomicU64::new(0);
static READ_FAIL_COUNT: AtomicU64 = AtomicU64::new(0);

pub fn _get_storage_stats() -> (u64, u64, u64, u64) {
    (
        WRITE_SUCCESS_COUNT.load(Ordering::Relaxed),
        WRITE_FAIL_COUNT.load(Ordering::Relaxed),
        READ_SUCCESS_COUNT.load(Ordering::Relaxed),
        READ_FAIL_COUNT.load(Ordering::Relaxed),
    )
}

pub enum LocalReadResult {
    Insufficient {
        read_count: usize,
    },
    Tampered {
        read_count: usize,
    },
    Expired {
        value: (u64, u64),
        read_count: usize,
    },
    Success {
        value: (u64, u64),
        read_count: usize,
        repair_failed: bool,
    },
}

fn derive_key(hkey: &str, salt: &str) -> [u8; 16] {
    let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), hkey.as_bytes());
    let mut okm = [0u8; 16];
    hk.expand(b"aes-128-gcm-key", &mut okm)
        .expect("HKDF expand should never fail");
    okm
}

fn derive_path(hkey: &str, salt: &str, slot: u8) -> PathBuf {
    debug_assert!(slot < 3);
    let mut h = Sha256::new();
    h.update(hkey.as_bytes());
    h.update(salt.as_bytes());
    h.update(&[slot]);
    let hex = format!("{:x}", h.finalize());
    let dir = dirs_next().unwrap_or_else(|| PathBuf::from("."));
    dir.join(format!(".lc_{}", &hex[..12]))
}

fn dirs_next() -> Option<PathBuf> {
    std::env::var("LICENSE_STORAGE_DIR")
        .ok()
        .map(PathBuf::from)
        .or_else(|| dirs::data_local_dir())
}

mod dirs {
    use std::path::PathBuf;
    pub fn data_local_dir() -> Option<PathBuf> {
        #[cfg(target_os = "linux")]
        {
            std::env::var("XDG_DATA_HOME")
                .ok()
                .map(PathBuf::from)
                .or_else(|| {
                    std::env::var("HOME")
                        .ok()
                        .map(|h| PathBuf::from(h).join(".local/share"))
                })
        }
        #[cfg(target_os = "macos")]
        {
            std::env::var("HOME")
                .ok()
                .map(|h| PathBuf::from(h).join("Library/Application Support"))
        }
        #[cfg(target_os = "windows")]
        {
            std::env::var("APPDATA").ok().map(PathBuf::from)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            None
        }
    }
}

fn write_slot(
    path: &PathBuf,
    key_bytes: &[u8; 16],
    activation: u64,
    expires: u64,
) -> Result<(), String> {
    let key = Key::<Aes128Gcm>::from_slice(key_bytes);
    let cipher = Aes128Gcm::new(key);
    let nonce_bytes = Aes128Gcm::generate_nonce(&mut OsRng);
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
    let mut out = nonce_bytes.to_vec();
    out.extend_from_slice(&ct);
    fs::write(path, &out).map_err(|e| format!("write: {e}"))?;
    WRITE_SUCCESS_COUNT.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

fn read_slot(path: &PathBuf, key_bytes: &[u8; 16]) -> Option<(u64, u64)> {
    let data = fs::read(path).ok()?;
    if data.len() != 44 {
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

pub fn write_all_replicas(hkey: &str, salt: &str, activation_ts: u64, expires_at: u64) {
    let key = derive_key(hkey, salt);
    for slot in 0..3u8 {
        let path = derive_path(hkey, salt, slot);
        if let Err(e) = write_slot(&path, &key, activation_ts, expires_at) {
            WRITE_FAIL_COUNT.fetch_add(1, Ordering::Relaxed);
            tracing::warn!("[Storage] replica slot {} write failed: {}", slot, e);
        }
    }
}

fn validate_and_return(val: (u64, u64), read_count: usize, repair_failed: bool) -> LocalReadResult {
    let now_u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let (act_ts, exp_ts) = val;

    // [BUG-CRIT-6 FIX] 使用 try_from 安全转换
    let now_i64 = i64::try_from(now_u64).unwrap_or(i64::MAX);

    if act_ts == 0 || exp_ts == 0 {
        return LocalReadResult::Tampered { read_count };
    }

    // 转换为 i64 进行检查
    let act_i64 = i64::try_from(act_ts).unwrap_or(i64::MAX);
    let exp_i64 = i64::try_from(exp_ts).unwrap_or(i64::MAX);

    if act_i64 > now_i64 + 300 {
        return LocalReadResult::Tampered { read_count };
    }
    if exp_i64 > now_i64 + MAX_LICENSE_PERIOD as i64 {
        return LocalReadResult::Tampered { read_count };
    }
    if act_i64 >= exp_i64 {
        return LocalReadResult::Tampered { read_count };
    }
    if now_u64 >= exp_ts {
        return LocalReadResult::Expired {
            value: val,
            read_count,
        };
    }
    LocalReadResult::Success {
        value: val,
        read_count,
        repair_failed,
    }
}

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
    if read_count < 2 {
        return LocalReadResult::Insufficient { read_count };
    }
    // 投票
    let mut counts: Vec<((u64, u64), usize)> = Vec::new();
    for &v in &values {
        if let Some(e) = counts.iter_mut().find(|(val, _)| *val == v) {
            e.1 += 1;
        } else {
            counts.push((v, 1));
        }
    }
    let majority_threshold = (read_count / 2) + 1;
    let best = counts.iter().max_by_key(|e| e.1).unwrap();
    let repair_failed = if best.1 < read_count {
        // [BUG-S1 FIX] 尝试修复不一致的副本
        if let Err(e) = write_all_replicas_return_err(hkey, salt, best.0 .0, best.0 .1) {
            tracing::warn!("[Storage] replica repair failed: {}", e);
            true
        } else {
            false
        }
    } else {
        false
    };
    if best.1 >= majority_threshold {
        validate_and_return(best.0, read_count, repair_failed)
    } else {
        LocalReadResult::Tampered { read_count }
    }
}

fn write_all_replicas_return_err(
    hkey: &str,
    salt: &str,
    activation_ts: u64,
    expires_at: u64,
) -> Result<(), String> {
    let key = derive_key(hkey, salt);
    for slot in 0..3u8 {
        let path = derive_path(hkey, salt, slot);
        write_slot(&path, &key, activation_ts, expires_at)?;
    }
    Ok(())
}
