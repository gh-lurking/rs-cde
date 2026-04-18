// client/src/storage.rs — 完整优化版
// 原有修复: BUG-04/07/NEW-9
// 新增修复: BUG-NEW-C(LocalReadResult 枚举，精确区分副本状态)

use aes_gcm::{
    Aes128Gcm, Key, Nonce,
    aead::rand_core::RngCore,
    aead::{Aead, KeyInit, OsRng},
};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

// BUG-NEW-C FIX: 枚举返回值，精确区分三种状态
pub enum LocalReadResult {
    /// 投票成功，返回 (value, 成功读取的副本数)
    Success {
        value: (u64, u64),
        read_count: usize,
    },
    /// 投票失败——副本数足够但无多数共识（可能遭篡改）
    Tampered { read_count: usize },
    /// 副本数不足（< 2）——可能首次运行或文件丢失
    Insufficient { read_count: usize },
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

// BUG-07 FIX: 写入时生成随机 nonce
// 文件格式：[random_nonce(12B)] + [ciphertext(32B)] = 44B
fn write_slot(
    path: &PathBuf,
    key_bytes: &[u8; 16],
    activation: u64,
    expires: u64,
) -> Result<(), String> {
    let key = Key::<Aes128Gcm>::from_slice(key_bytes);
    let cipher = Aes128Gcm::new(key);

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes); // BUG-07 FIX: 每次写入随机 nonce
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

// BUG-07 FIX: 读取时从文件头读 nonce
fn read_slot(path: &PathBuf, key_bytes: &[u8; 16]) -> Option<(u64, u64)> {
    let data = fs::read(path).ok()?;
    if data.len() != 44 {
        return None; // 12 nonce + 32 ciphertext
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

/// BUG-NEW-C FIX: 返回 LocalReadResult 枚举，精确区分三种状态
/// BUG-04 FIX: 三副本严格多数投票（> N/2）
/// BUG-NEW-9 FIX: 修复逻辑覆盖损坏/缺失的槽位
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

    // 副本数不足（< 2）
    if read_count < 2 {
        return LocalReadResult::Insufficient { read_count };
    }

    // 多数投票
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
        // BUG-NEW-9 FIX: 修复所有不一致的副本，包括损坏/缺失的槽位
        if best_count < 3 {
            for slot in 0..3u8 {
                let path = derive_path(hkey, salt, slot);
                let slot_val = read_slot(&path, &key);
                let needs_repair = match slot_val {
                    Some(pair) => pair != best_val,
                    None => true, // BUG-NEW-9 FIX: 覆盖损坏/缺失
                };
                if needs_repair {
                    if let Err(e) = write_slot(&path, &key, best_val.0, best_val.1) {
                        tracing::warn!("[Storage] 修复副本 {} 失败: {}", slot, e);
                    } else {
                        tracing::info!("[Storage] 已修复副本 {} (含缺失/损坏槽)", slot);
                    }
                }
            }
        }
        LocalReadResult::Success {
            value: best_val,
            read_count,
        }
    } else {
        // 平票或无多数 → 视为篡改（BUG-NEW-C FIX: 精确枚举值）
        LocalReadResult::Tampered { read_count }
    }
}

/// 向所有三个槽位写入最新数据
pub fn write_all_replicas(hkey: &str, salt: &str, activation: u64, expires: u64) {
    let key = derive_key(hkey, salt);
    for slot in 0..3u8 {
        let path = derive_path(hkey, salt, slot);
        if let Err(e) = write_slot(&path, &key, activation, expires) {
            tracing::warn!("[Storage] 写入副本 {} 失败: {}", slot, e);
        }
    }
}
