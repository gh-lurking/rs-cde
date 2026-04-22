// client/src/storage.rs
//
// [BUG-S1 FIX] 多数派选举：read_count=2 要求全票，read_count=3 要求>=2票
// [BUG-S2 NOTE] validate_and_return 中的 act_ts 未来检查依赖系统时钟，
//               主防线是 time_guard + validate_system_time，此为辅助
use aes_gcm::{
    aead::{Aead, OsRng},
    AeadCore, Aes128Gcm, Key, KeyInit, Nonce,
};
use hkdf::Hkdf;
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
    // [BUG-M1 NOTE] assert 防止扩展 slot 数量时路径回绕覆盖
    assert!(slot < 16, "slot must be < 16 to prevent path collision");
    let mut h = sha2::Sha256::new();
    use sha2::Digest;
    h.update(hkey.as_bytes());
    h.update(salt.as_bytes());
    h.update(&[slot]);
    let digest = format!("{:x}", h.finalize());
    let base = std::env::var("LICENSE_CACHE_DIR").unwrap_or_else(|_| ".license_cache".to_string());
    PathBuf::from(base)
        .join(&digest[..16])
        .join(format!("{:02x}.dat", slot))
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
            tracing::warn!("[Storage] 写入副本 {} 失败: {}", slot, e);
        }
    }
}

fn validate_and_return(val: (u64, u64), read_count: usize, repair_failed: bool) -> LocalReadResult {
    let now_u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let (act_ts, exp_ts) = val;

    if act_ts > now_u64 + 300 {
        return LocalReadResult::Tampered { read_count };
    }
    if exp_ts == 0 || exp_ts > now_u64 + MAX_LICENSE_PERIOD {
        return LocalReadResult::Tampered { read_count };
    }
    if act_ts >= exp_ts {
        return LocalReadResult::Tampered { read_count };
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

    // 至少 2 副本可读，单副本无法证明未被篡改
    if read_count < 2 {
        return LocalReadResult::Insufficient { read_count };
    }

    // 多数派计票
    let mut counts: Vec<((u64, u64), usize)> = Vec::new();
    for &v in &values {
        if let Some(e) = counts.iter_mut().find(|(val, _)| *val == v) {
            e.1 += 1;
        } else {
            counts.push((v, 1));
        }
    }

    let (winner, winner_count) = counts.iter().max_by_key(|(_, c)| *c).copied().unwrap();

    // [BUG-S1 FIX] 严格多数派：
    // read_count=2 → 要求 2 票（完全一致）
    // read_count=3 → 要求 2 票（2/3 多数）
    let min_votes = if read_count == 3 { 2 } else { read_count };

    if winner_count < min_votes {
        return LocalReadResult::Tampered { read_count };
    }

    // 修复少数派副本
    let repair_key = derive_key(hkey, salt);
    let mut repair_failed = false;
    for slot in 0..3u8 {
        let path = derive_path(hkey, salt, slot);
        match read_slot(&path, &repair_key) {
            Some(v) if v == winner => {} // 已是多数派，无需修复
            _ => {
                if write_slot(&path, &repair_key, winner.0, winner.1).is_err() {
                    repair_failed = true;
                }
            }
        }
    }

    validate_and_return(winner, read_count, repair_failed)
}
