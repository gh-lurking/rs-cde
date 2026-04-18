// client/src/storage.rs — 优化版（修复 BUG-04/07）

// BUG-07 FIX: 写入时使用 OsRng 生成随机 nonce，读取时从文件头读取 nonce
// BUG-04 FIX: read_local_record_with_count() 返回副本数，调用方做多数投票校验
//             当 best_count * 2 > replica_count 时才信任（严格多数）

use aes_gcm::{
    Aes128Gcm, Key, Nonce,
    aead::rand_core::RngCore,
    aead::{Aead, KeyInit, OsRng},
};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use tracing;
// ─── 密钥派生（与写入/读取共用）──────────────────────────────────────────────

fn derive_key(hkey: &str, salt: &str) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(salt.as_bytes());
    h.update(hkey.as_bytes());
    h.finalize()[..16].try_into().unwrap()
}

// ─── 路径派生（三个不同槽位）─────────────────────────────────────────────────

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

// ─── BUG-07 FIX: 写入时生成随机 nonce ────────────────────────────────────────

// 文件格式：[random_nonce(12)] + [ciphertext(16 plaintext + 16 GCM tag = 32)] = 44 字节

fn write_slot(
    path: &PathBuf,
    key_bytes: &[u8; 16],
    activation: u64,
    expires: u64,
) -> Result<(), String> {
    let key = Key::<Aes128Gcm>::from_slice(key_bytes);
    let cipher = Aes128Gcm::new(key);

    // BUG-07 FIX: 每次写入生成全新随机 nonce
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

    let mut out = nonce_bytes.to_vec(); // 12 字节随机 nonce
    out.extend_from_slice(&ct); // 32 字节密文
    fs::write(path, &out).map_err(|e| format!("write: {e}"))
}

// ─── BUG-07 FIX: 读取时从文件头读 nonce ──────────────────────────────────────

fn read_slot(path: &PathBuf, key_bytes: &[u8; 16]) -> Option<(u64, u64)> {
    let data = fs::read(path).ok()?;

    if data.len() != 44 {
        return None;
    }

    // BUG-07 FIX: nonce 从文件头读取，不再用 derive_nonce
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

// ─── 公开 API ─────────────────────────────────────────────────────────────────

/// BUG-04 FIX: 读取（副本数、调用方做多数投票校验）
///
/// 使用 replica_count >= 2 且严格多数（best_count * 2 > replica_count）才信任
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

    // 最高票值
    let (best_val, best_count) = counts.iter().max_by_key(|(_, c)| *c).copied().unwrap();

    // BUG-04 FIX: 严格多数（> N/2）才信任
    if best_count * 2 > replica_count {
        // BUG-04: 若有副本与多数不一致，修复（用最新多数值覆写坏副本）
        if best_count < replica_count {
            for slot in 0..3u8 {
                let path = derive_path(hkey, salt, slot);
                if let Some(pair) = read_slot(&path, &key) {
                    if pair != best_val {
                        // 修复损坏副本（静默，失败无所谓，下次会重试）
                        let _ = write_slot(&path, &key, best_val.0, best_val.1);
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
