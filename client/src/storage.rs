// client/src/storage.rs — 优化版 v10
// OPT-5 FIX: 补充缺失的 MAX_LICENSE_PERIOD 常量定义
// OPT-3 FIX: LocalReadResult::Success 新增 repair_failed: bool
// MAJOR-A FIX: N=2:0 误判修复（best_count*2 > read_count）
// MAJOR-B FIX: best_val 值域合理性验证（防止篡改的大值通过投票）

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes128Gcm, Key, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// [OPT-5 FIX] 本地缓存记录的合理期限上限：20 年（秒）
const MAX_LICENSE_PERIOD: u64 = 20 * 365 * 86400;

/// 本地副本读取结果
pub enum LocalReadResult {
    /// 可用副本数不足
    Insufficient { read_count: usize },
    /// 检测到篡改
    Tampered { read_count: usize },
    /// 读取成功
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
        .expect("HKDF expand 16 bytes should never fail");
    okm
}

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
    fs::write(path, &out).map_err(|e| format!("write: {e}"))
}

fn read_slot(path: &PathBuf, key_bytes: &[u8; 16]) -> Option<(u64, u64)> {
    let data = fs::read(path).ok()?;
    if data.len() != 44 {
        return None;
    }

    let key = Key::<Aes128Gcm>::from_slice(key_bytes);
    let cipher = Aes128Gcm::new(key);
    let nonce = Nonce::from_slice(&data[..12]);
    let plain = cipher.decrypt(nonce, &data[12..]).ok()?;

    if plain.len() != 16 {
        return None;
    }

    let act = u64::from_le_bytes(plain[..8].try_into().unwrap());
    let exp = u64::from_le_bytes(plain[8..].try_into().unwrap());
    Some((act, exp))
}

/// 写入 3 个副本
pub fn write_all_replicas(hkey: &str, salt: &str, activation_ts: u64, expires_at: u64) {
    let key = derive_key(hkey, salt);
    for slot in 0..3u8 {
        let path = derive_path(hkey, salt, slot);
        if let Err(e) = write_slot(&path, &key, activation_ts, expires_at) {
            tracing::warn!("[Storage] Replica {} write failed: {}", slot, e);
        }
    }
}

/// 读取本地副本，多数票仲裁
pub fn read_local_record(hkey: &str, salt: &str) -> LocalReadResult {
    let key = derive_key(hkey, salt);
    let mut values: Vec<(u64, u64)> = Vec::new();

    for slot in 0..3u8 {
        let path = derive_path(hkey, salt, slot);
        if let Some(pair) = read_slot(&path, &key) {
            values.push(pair);
        }
    }

    let read_count = values.len();

    // [MAJOR-A FIX] 先检查 read_count（至少 2 个才能仲裁）
    if read_count < 2 {
        return LocalReadResult::Insufficient { read_count };
    }

    // 多数票计数
    let mut counts: Vec<((u64, u64), usize)> = Vec::new();
    for &v in &values {
        if let Some(entry) = counts.iter_mut().find(|(val, _)| *val == v) {
            entry.1 += 1;
        } else {
            counts.push((v, 1));
        }
    }

    let (best_val, best_count) = counts.iter().max_by_key(|(_, c)| *c).copied().unwrap();

    // [MAJOR-A FIX] 严格过半数
    if best_count * 2 <= read_count {
        return LocalReadResult::Tampered { read_count };
    }

    let now_u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // [MAJOR-B FIX] 值域合理性验证
    let (act_ts, exp_ts) = best_val;
    if act_ts > now_u64 + 300 {
        tracing::warn!(
            "[Storage] Sanity check failed: activation_ts({}) in future (now={})",
            act_ts,
            now_u64
        );
        return LocalReadResult::Tampered { read_count };
    }

    // [OPT-5 FIX] MAX_LICENSE_PERIOD 现在已正确定义
    if exp_ts == 0 || exp_ts > now_u64 + MAX_LICENSE_PERIOD {
        tracing::warn!(
            "[Storage] Sanity check failed: exp_ts({}) out of range",
            exp_ts
        );
        return LocalReadResult::Tampered { read_count };
    }

    if act_ts == 0 || exp_ts <= act_ts {
        tracing::warn!(
            "[Storage] Sanity check failed: invalid ts pair ({}, {})",
            act_ts,
            exp_ts
        );
        return LocalReadResult::Tampered { read_count };
    }

    // 修复不一致副本
    let mut repair_failed = false;
    if best_count < read_count {
        for (slot, &val) in values.iter().enumerate() {
            let path = derive_path(hkey, salt, slot as u8);
            let needs_repair = match Some(val) {
                Some(v) => v != best_val,
                None => true,
            };
            if needs_repair {
                if let Err(e) = write_slot(&path, &key, best_val.0, best_val.1) {
                    tracing::warn!("[Storage] Replica {} repair failed: {}", slot, e);
                    repair_failed = true;
                } else {
                    tracing::info!("[Storage] Replica {} repaired", slot);
                }
            }
        }
    }

    LocalReadResult::Success {
        value: best_val,
        read_count,
        repair_failed,
    }
}
