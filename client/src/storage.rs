// client/src/storage.rs — 优化版 v2
// MAJOR-4 FIX: 1个副本存在时尝试自愈（原代码 read_count<2 直接报错）
// 原有修复全部保留（BUG-04/07/NEW-9/NEW-C/NEW-E）
use aes_gcm::{
    Aes128Gcm, Key, Nonce,
    aead::rand_core::RngCore,
    aead::{Aead, KeyInit, OsRng},
};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

pub enum LocalReadResult {
    Success {
        value: (u64, u64),
        read_count: usize,
    },
    Tampered {
        read_count: usize,
    },
    Insufficient {
        read_count: usize,
    },
}

fn derive_key(hkey: &str, salt: &str) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(salt.as_bytes());
    h.update(hkey.as_bytes());
    h.finalize()[..16].try_into().unwrap()
}

fn derive_path(hkey: &str, salt: &str, slot: u8) -> PathBuf {
    let mut h = Sha256::new();
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
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
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
    let stored_nonce = &data[..12];
    let key = Key::<Aes128Gcm>::from_slice(key_bytes);
    let cipher = Aes128Gcm::new(key);
    let nonce = Nonce::from_slice(stored_nonce);
    let plain = cipher.decrypt(nonce, &data[12..]).ok()?;
    if plain.len() != 16 {
        return None;
    }
    let act = u64::from_le_bytes(plain[..8].try_into().unwrap());
    let exp = u64::from_le_bytes(plain[8..].try_into().unwrap());
    Some((act, exp))
}

/// MAJOR-4 FIX: 单副本时尝试自愈，0副本才 Insufficient
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

    // MAJOR-4 FIX: 0 副本才报 Insufficient
    if read_count == 0 {
        return LocalReadResult::Insufficient { read_count: 0 };
    }

    // MAJOR-4 FIX: 1 个副本 → 尝试自愈其余两个，返回 Success（附带警告）
    if read_count == 1 {
        let only_val = values[0];
        tracing::warn!("[Storage] 仅找到 1/3 个副本，尝试自愈其余副本");
        for slot in 0..3u8 {
            let path = derive_path(hkey, salt, slot);
            let existing = read_slot(&path, &key);
            if existing != Some(only_val) {
                if let Err(e) = write_slot(&path, &key, only_val.0, only_val.1) {
                    tracing::warn!("[Storage] 自愈副本 {} 失败: {}", slot, e);
                } else {
                    tracing::info!("[Storage] 已自愈副本 {}", slot);
                }
            }
        }
        return LocalReadResult::Success {
            value: only_val,
            read_count: 1,
        };
    }

    // read_count >= 2：多数投票
    let mut counts: Vec<((u64, u64), usize)> = Vec::new();
    for &v in &values {
        if let Some(entry) = counts.iter_mut().find(|(val, _)| *val == v) {
            entry.1 += 1;
        } else {
            counts.push((v, 1));
        }
    }
    let (best_val, best_count) = counts.iter().max_by_key(|(_, c)| *c).copied().unwrap();

    if best_count * 2 > read_count {
        // 修复不一致的副本
        if best_count < read_count {
            for slot in 0..3u8 {
                let path = derive_path(hkey, salt, slot);
                let needs_repair = match read_slot(&path, &key) {
                    Some(pair) => pair != best_val,
                    None => true,
                };
                if needs_repair {
                    if let Err(e) = write_slot(&path, &key, best_val.0, best_val.1) {
                        tracing::warn!("[Storage] 修复副本 {} 失败: {}", slot, e);
                    } else {
                        tracing::info!("[Storage] 已修复副本 {}", slot);
                    }
                }
            }
        }
        LocalReadResult::Success {
            value: best_val,
            read_count,
        }
    } else {
        LocalReadResult::Tampered { read_count }
    }
}

pub fn write_all_replicas(hkey: &str, salt: &str, activation: u64, expires: u64) {
    let key = derive_key(hkey, salt);
    for slot in 0..3u8 {
        let path = derive_path(hkey, salt, slot);
        if let Err(e) = write_slot(&path, &key, activation, expires) {
            tracing::warn!("[Storage] 写入副本 {} 失败: {}", slot, e);
        }
    }
}
