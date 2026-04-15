// src/storage.rs — AES-GCM 三重存储，确定性路径派生
use aes_gcm::{
    Aes128Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use sha2::{Sha256, Digest};
use std::path::PathBuf;
use std::fs;

/// 从 HKEY + SALT 确定性地派生 AES-128 密钥（16字节）
fn derive_key(hkey: &str, salt: &str) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(salt.as_bytes());
    hasher.update(hkey.as_bytes());
    let result = hasher.finalize();
    result[..16].try_into().unwrap()
}

/// 从 HKEY 确定性地派生 Nonce（12字节），每个路径槽不同
fn derive_nonce(hkey: &str, slot: u8) -> [u8; 12] {
    let mut hasher = Sha256::new();
    hasher.update(b"NONCE_SLOT");
    hasher.update([slot]);
    hasher.update(hkey.as_bytes());
    let result = hasher.finalize();
    result[..12].try_into().unwrap()
}

/// 从 HKEY + SALT + index 确定性派生存储路径（每次运行结果相同）
/// 路径形如：~/.cache/.sys/a3f2c1d9/slot0
fn derive_path(hkey: &str, salt: &str, slot: u8) -> PathBuf {
    // 目录名：SHA256(SALT + HKEY)[0..4] → hex（8字符）
    let mut h = Sha256::new();
    h.update(salt.as_bytes());
    h.update(hkey.as_bytes());
    let digest = h.finalize();
    let dir_name = format!("{:02x}{:02x}{:02x}{:02x}",
        digest[0], digest[1], digest[2], digest[3]);

    // 文件名：slot 索引不同，文件名不同
    let file_names = ["index.db", "cache.bin", "meta.dat"];
    let file_name = file_names[slot as usize % 3];

    // 基础目录（3个不同的系统目录）
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| "/tmp".to_string());

    let base_dirs = [
        format!("{}/.cache/.sys/{}", home, dir_name),   // 槽0
        format!("{}/.local/share/.sys/{}", home, dir_name), // 槽1
        format!("{}/.config/.sys/{}", home, dir_name),   // 槽2
    ];

    PathBuf::from(&base_dirs[slot as usize % 3]).join(file_name)
}

/// 加密 activation_ts → 写入文件
/// 文件格式：[nonce(12)] ++ [ciphertext(8)] ++ [tag(16)] = 36 字节
fn write_slot(path: &PathBuf, key_bytes: &[u8;16], nonce_bytes: &[u8;12], ts: u64) {
    let key = Key::<Aes128Gcm>::from_slice(key_bytes);
    let cipher = Aes128Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = ts.to_le_bytes();

    if let Ok(ciphertext) = cipher.encrypt(nonce, plaintext.as_ref()) {
        // ciphertext 包含 8字节密文 + 16字节 GCM Tag = 24字节
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let mut file_data = nonce_bytes.to_vec();  // 12 字节 nonce
        file_data.extend_from_slice(&ciphertext);   // 24 字节
        // 总计 36 字节
        let _ = fs::write(path, &file_data);
    }
}

/// 从文件解密 activation_ts
fn read_slot(path: &PathBuf, key_bytes: &[u8;16], nonce_bytes: &[u8;12]) -> Option<u64> {
    let data = fs::read(path).ok()?;
    if data.len() != 36 { return None; }

    // 从文件头提取 nonce（与写入时相同，确定性）
    let stored_nonce = &data[..12];
    // 校验 nonce 是否与期望一致（防止文件被从其他HKEY复制）
    if stored_nonce != nonce_bytes { return None; }

    let key = Key::<Aes128Gcm>::from_slice(key_bytes);
    let cipher = Aes128Gcm::new(key);
    let nonce = Nonce::from_slice(stored_nonce);

    let plaintext = cipher.decrypt(nonce, &data[12..]).ok()?;
    if plaintext.len() != 8 { return None; }
    Some(u64::from_le_bytes(plaintext.try_into().unwrap()))
}

/// 读取三个副本，采用多数票原则
pub fn read_activation_ts(hkey: &str, salt: &str) -> Option<u64> {
    let key = derive_key(hkey, salt);
    let mut values: Vec<u64> = Vec::new();

    for slot in 0..3u8 {
        let path = derive_path(hkey, salt, slot);
        let nonce = derive_nonce(hkey, slot);
        if let Some(ts) = read_slot(&path, &key, &nonce) {
            values.push(ts);
        }
    }

    if values.is_empty() { return None; }

    // 多数票：取出现次数最多的值（防止单副本被篡改）
    values.sort();
    let mut best = (values[0], 1usize);
    let mut cur = (values[0], 1usize);
    for &v in &values[1..] {
        if v == cur.0 { cur.1 += 1; } else { cur = (v, 1); }
        if cur.1 > best.1 { best = cur; }
    }
    Some(best.0)
}

/// 将 activation_ts 写入全部三个副本
pub fn write_all_replicas(hkey: &str, salt: &str, ts: u64) {
    let key = derive_key(hkey, salt);
    for slot in 0..3u8 {
        let path = derive_path(hkey, salt, slot);
        let nonce = derive_nonce(hkey, slot);
        write_slot(&path, &key, &nonce, ts);
    }
}