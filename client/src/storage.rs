// client/src/storage.rs — 优化版（修复 BUG-04/07）

// BUG-07 FIX: 写入时使用 OsRng 生成随机 nonce 存入文件头，放弃固定 derive_nonce
// BUG-04 FIX: read_local_record_with_count() 返回读取成功的副本数，
//             调用方用严格多数（>=2）判断是否可信

use aes_gcm::{
    Aes128Gcm, Key, Nonce,
    aead::rand_core::RngCore,
    aead::{Aead, KeyInit, OsRng},
};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

// ─── 密钥派生（与原版相同）───────────────────────────────────────────────────
fn derive_key(hkey: &str, salt: &str) -> [u8; 16] {
    let mut h = Sha256::new();

    h.update(salt.as_bytes());
    h.update(hkey.as_bytes());
    h.finalize()[..16].try_into().unwrap()
}

// ─── 文件路径派生（与原版相同）───────────────────────────────────────────────

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

// ─── BUG-07 FIX: 写入时使用随机 nonce ────────────────────────────────────────

// 文件格式：[random_nonce(12)] ++ [ciphertext(16 plaintext + 16 GCM tag = 32)] = 44 字节

fn write_slot(path: &PathBuf, key_bytes: &[u8; 16], activation: u64, expires: u64) {
    let key = Key::<Aes128Gcm>::from_slice(key_bytes);

    let cipher = Aes128Gcm::new(key);

    // BUG-07 FIX: 每次写入生成新随机 nonce

    let mut nonce_bytes = [0u8; 12];

    OsRng.fill_bytes(&mut nonce_bytes);

    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut plain = [0u8; 16];

    plain[..8].copy_from_slice(&activation.to_le_bytes());

    plain[8..].copy_from_slice(&expires.to_le_bytes());

    if let Ok(ct) = cipher.encrypt(nonce, plain.as_ref()) {
        if let Some(p) = path.parent() {
            let _ = fs::create_dir_all(p);
        }

        let mut out = nonce_bytes.to_vec(); // 12 字节随机 nonce

        out.extend_from_slice(&ct); // 32 字节密文

        let _ = fs::write(path, &out); // 总 44 字节
    }
}

// ─── 读取单个槽（从文件头取 nonce）───────────────────────────────────────────

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

// ─── 公开 API ──────────────────────────────────────────────────────────────────

/// BUG-04 FIX: 返回 (多数票结果, 成功读取的副本数)

/// 调用方用 replica_count >= 2 判断结果是否可信（严格多数）

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

    // BUG-04 FIX: 统计每个值出现次数，取出现次数 > replica_count/2 的值（严格多数）

    let mut counts: Vec<((u64, u64), usize)> = Vec::new();

    for &v in &values {
        if let Some(entry) = counts.iter_mut().find(|(val, _)| *val == v) {
            entry.1 += 1;
        } else {
            counts.push((v, 1));
        }
    }

    // 找出现次数最多的
    let (best_val, best_count) = counts.iter().max_by_key(|(_, c)| *c).copied().unwrap();

    // 严格多数：出现次数必须 > 总读取数 / 2
    if best_count * 2 > replica_count {
        // BUG-04: 若存在不一致副本，触发修复写入（用多数票值覆盖异常副本）

        if best_count < replica_count {
            tracing::warn!(
                "[License] 检测到副本不一致（{}/{}），执行修复写入",
                best_count,
                replica_count
            );

            write_all_replicas(hkey, salt, best_val.0, best_val.1);
        }

        (Some(best_val), replica_count)
    } else {
        // 没有严格多数（如 3 副本全不同），视为不可信
        tracing::error!("[License] 三副本无多数共识，数据可能被篡改");
        (None, replica_count)
    }
}

/// 兼容性封装（供 license_guard 旧调用路径使用）

pub fn read_local_record(hkey: &str, salt: &str) -> Option<(u64, u64)> {
    read_local_record_with_count(hkey, salt).0
}

/// 将 (activation_ts, expires_at) 写入全部三个副本（每次使用新随机 nonce）
pub fn write_all_replicas(hkey: &str, salt: &str, activation: u64, expires: u64) {
    let key = derive_key(hkey, salt);
    for slot in 0..3u8 {
        let path = derive_path(hkey, salt, slot);
        write_slot(&path, &key, activation, expires);
    }
}
