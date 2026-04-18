// client/src/storage.rs — 最终优化版
// BUG-04  FIX: 三份副本 + 严格多数投票（> N/2）才信任，防单文件篡改
// BUG-07  FIX: 写入时用 OsRng 生成随机 nonce，读取时从文件头读取 nonce
// BUG-NEW-9 FIX: 副本修复逻辑同时修复"读取失败（损坏/缺失）"的槽位

use aes_gcm::{
    Aes128Gcm, Key, Nonce,
    aead::rand_core::RngCore,
    aead::{Aead, KeyInit, OsRng},
};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

// ─── 密钥派生（与写入/读取共用）──────────────────────────────────────────────
fn derive_key(hkey: &str, salt: &str) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(salt.as_bytes());
    h.update(hkey.as_bytes());
    h.finalize()[..16].try_into().unwrap()
}

// ─── 路径派生（三个不同槽位，存储在不同目录和文件名）──────────────────────
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

    // 三个不同目录（Linux/macOS 隐藏目录）
    let bases = [
        format!("{}/.cache/.sys/{}", home, dir_name),
        format!("{}/.local/share/.sys/{}", home, dir_name),
        format!("{}/.config/.sys/{}", home, dir_name),
    ];
    PathBuf::from(&bases[slot as usize % 3]).join(files[slot as usize % 3])
}

// ─── BUG-07 FIX: 写入时生成随机 nonce ──────────────────────────────────────
// 文件格式：[random_nonce(12B)] + [ciphertext(32B)] = 44B
fn write_slot(
    path: &PathBuf,
    key_bytes: &[u8; 16],
    activation: u64,
    expires: u64,
) -> Result<(), String> {
    let key = Key::<Aes128Gcm>::from_slice(key_bytes);
    let cipher = Aes128Gcm::new(key);

    // BUG-07 FIX: 每次写入生成全新随机 nonce（OsRng = 系统密码学随机源）
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

    // ✅ nonce 前置写入文件（读取时从文件头恢复）
    let mut out = nonce_bytes.to_vec(); // 12 字节随机 nonce
    out.extend_from_slice(&ct); // 32 字节密文（16B 明文 + 16B GCM tag）
    fs::write(path, &out).map_err(|e| format!("write: {e}"))
}

// ─── BUG-07 FIX: 读取时从文件头读 nonce ─────────────────────────────────────
fn read_slot(path: &PathBuf, key_bytes: &[u8; 16]) -> Option<(u64, u64)> {
    let data = fs::read(path).ok()?;
    if data.len() != 44 {
        return None; // 12 nonce + 32 ciphertext
    }

    // BUG-07 FIX: nonce 从文件头读取（不再重新派生固定 nonce）
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

// ─── 公开 API ─────────────────────────────────────────────────────────────
/// BUG-04 FIX: 读取三个副本，严格多数投票（best_count * 2 > replica_count）才信任
/// BUG-NEW-9 FIX: 修复逻辑同时覆盖"读取失败（损坏/缺失）"的槽位，确保副本完全恢复
/// 返回 (Option<(u64,u64)>, 成功读取的副本数)
pub fn read_local_record_with_count(hkey: &str, salt: &str) -> (Option<(u64, u64)>, usize) {
    let key = derive_key(hkey, salt);
    let mut values: Vec<(u64, u64)> = Vec::new();

    for slot in 0..3u8 {
        let path = derive_path(hkey, salt, slot);
        if let Some(pair) = read_slot(&path, &key) {
            values.push(pair);
        }
    }

    let replica_count = values.len();

    if values.is_empty() {
        return (None, 0);
    }

    // BUG-04 FIX: 投票找多数值
    let mut counts: Vec<((u64, u64), usize)> = Vec::new();
    for &v in &values {
        if let Some(entry) = counts.iter_mut().find(|(val, _)| *val == v) {
            entry.1 += 1;
        } else {
            counts.push((v, 1));
        }
    }

    let (best_val, best_count) = counts.iter().max_by_key(|(_, c)| *c).copied().unwrap();

    // 严格多数（> N/2）才信任
    if best_count * 2 > replica_count {
        // BUG-NEW-9 FIX: 修复所有不一致的副本，包括损坏/缺失的槽位
        // 原版只修复"读取成功但值不同"的副本，忽略了损坏/缺失槽
        if best_count < 3 {
            for slot in 0..3u8 {
                let path = derive_path(hkey, salt, slot);
                let needs_repair = match read_slot(&path, &key) {
                    Some(pair) => pair != best_val, // 值不一致
                    None => true,                   // 读取失败（损坏或缺失）← BUG-NEW-9 FIX
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
        (Some(best_val), replica_count)
    } else {
        // 平票或无多数 → 视为篡改
        eprintln!(
            "[Storage] 本地副本无法形成多数共识（{}/{}），可能遭篡改",
            best_count, replica_count
        );
        (None, replica_count)
    }
}

/// 向所有三个槽位写入最新数据（BUG-07 FIX: write_slot 返回 Result，记录失败）
pub fn write_all_replicas(hkey: &str, salt: &str, activation: u64, expires: u64) {
    let key = derive_key(hkey, salt);
    for slot in 0..3u8 {
        let path = derive_path(hkey, salt, slot);
        if let Err(e) = write_slot(&path, &key, activation, expires) {
            tracing::warn!("[Storage] 写入副本 {} 失败: {}", slot, e);
        }
    }
}
