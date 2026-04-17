// client/src/storage.rs — AES-GCM 三重存储（updated）
//
// ✅ 变更: 同时存储 activation_ts 和 expires_at 两个 u64 值
//   原版只存 activation_ts，新版每个槽存 16 字节明文（两个 u64）
//   文件格式：[nonce(12)] ++ [ciphertext(16+16tag)] = 44 字节
//
//   新增/修改的公开 API：
//     write_all_replicas(hkey, salt, activation_ts, expires_at)  ← 多一个参数
//     read_local_record(hkey, salt) -> Option<(u64, u64)>        ← 新函数，返回两值

use aes_gcm::{
    Aes128Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use sha2::{Sha256, Digest};
use std::path::PathBuf;
use std::fs;

// ─── 内部工具函数（与原版相同，无变更）────────────────────────────────────────

fn derive_key(hkey: &str, salt: &str) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(salt.as_bytes());
    h.update(hkey.as_bytes());
    h.finalize()[..16].try_into().unwrap()
}

fn derive_nonce(hkey: &str, slot: u8) -> [u8; 12] {
    let mut h = Sha256::new();
    h.update(b"NONCE_SLOT");
    h.update([slot]);
    h.update(hkey.as_bytes());
    h.finalize()[..12].try_into().unwrap()
}

fn derive_path(hkey: &str, salt: &str, slot: u8) -> PathBuf {
    let mut h = Sha256::new();
    h.update(salt.as_bytes());
    h.update(hkey.as_bytes());
    let d        = h.finalize();
    let dir_name = format!("{:02x}{:02x}{:02x}{:02x}", d[0], d[1], d[2], d[3]);
    let files    = ["index.db", "cache.bin", "meta.dat"];
    let home     = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| "/tmp".to_string());
    let bases = [
        format!("{}/.cache/.sys/{}", home, dir_name),
        format!("{}/.local/share/.sys/{}", home, dir_name),
        format!("{}/.config/.sys/{}", home, dir_name),
    ];
    PathBuf::from(&bases[slot as usize % 3]).join(files[slot as usize % 3])
}

// ─── ✅ 变更：加密两个 u64 值（activation_ts + expires_at）──────────────────

/// 加密 (activation_ts, expires_at) → 写入文件
/// 文件格式：nonce(12) ++ ciphertext(16+16tag) = 44 字节
fn write_slot(
    path:         &PathBuf,
    key_bytes:    &[u8; 16],
    nonce_bytes:  &[u8; 12],
    activation:   u64,
    expires:      u64,
) {
    let key    = Key::<Aes128Gcm>::from_slice(key_bytes);
    let cipher = Aes128Gcm::new(key);
    let nonce  = Nonce::from_slice(nonce_bytes);

    // 明文 = activation_ts(8字节 LE) ++ expires_at(8字节 LE) = 16字节
    let mut plain = [0u8; 16];
    plain[..8].copy_from_slice(&activation.to_le_bytes());
    plain[8..].copy_from_slice(&expires.to_le_bytes());

    if let Ok(ct) = cipher.encrypt(nonce, plain.as_ref()) {
        // ct = 16字节密文 + 16字节 GCM Tag = 32字节
        if let Some(p) = path.parent() { let _ = fs::create_dir_all(p); }
        let mut out = nonce_bytes.to_vec(); // 12字节
        out.extend_from_slice(&ct);         // 32字节
        // 总计 44 字节
        let _ = fs::write(path, &out);
    }
}

/// 从文件解密 (activation_ts, expires_at)
fn read_slot(
    path:        &PathBuf,
    key_bytes:   &[u8; 16],
    nonce_bytes: &[u8; 12],
) -> Option<(u64, u64)> {
    let data = fs::read(path).ok()?;
    if data.len() != 44 { return None; }

    let stored_nonce = &data[..12];
    if stored_nonce != nonce_bytes { return None; }

    let key    = Key::<Aes128Gcm>::from_slice(key_bytes);
    let cipher = Aes128Gcm::new(key);
    let nonce  = Nonce::from_slice(stored_nonce);
    let plain  = cipher.decrypt(nonce, &data[12..]).ok()?;
    if plain.len() != 16 { return None; }

    let act = u64::from_le_bytes(plain[..8].try_into().unwrap());
    let exp = u64::from_le_bytes(plain[8..].try_into().unwrap());
    Some((act, exp))
}

// ─── 公开 API ─────────────────────────────────────────────────────────────────

/// ✅ 变更: 读取三副本，返回 (activation_ts, expires_at)，多数票原则
pub fn read_local_record(hkey: &str, salt: &str) -> Option<(u64, u64)> {
    let key = derive_key(hkey, salt);
    let mut values: Vec<(u64, u64)> = Vec::new();
    for slot in 0..3u8 {
        let path  = derive_path(hkey, salt, slot);
        let nonce = derive_nonce(hkey, slot);
        if let Some(pair) = read_slot(&path, &key, &nonce) {
            values.push(pair);
        }
    }
    if values.is_empty() { return None; }

    // 多数票：按 activation_ts 排序后取出现次数最多的对
    values.sort_by_key(|v| v.0);
    let mut best = (values[0], 1usize);
    let mut cur  = (values[0], 1usize);
    for &v in &values[1..] {
        if v == cur.0 { cur.1 += 1; } else { cur = (v, 1); }
        if cur.1 > best.1 { best = cur; }
    }
    Some(best.0)
}

/// ✅ 变更: 将 (activation_ts, expires_at) 写入全部三个副本
pub fn write_all_replicas(hkey: &str, salt: &str, activation: u64, expires: u64) {
    let key = derive_key(hkey, salt);
    for slot in 0..3u8 {
        let path  = derive_path(hkey, salt, slot);
        let nonce = derive_nonce(hkey, slot);
        write_slot(&path, &key, &nonce, activation, expires);
    }
}