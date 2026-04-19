// client/src/storage.rs — 优化版 v7
// ✅ MAJOR-B FIX: read_count < 2 时提前返回 Insufficient，
//   防止 counts.iter().max_by_key().unwrap() 在 read_count=0 时 panic
use aes_gcm::{
    Aes128Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use hkdf::Hkdf;
use sha2::Sha256;
use std::fs;
use std::path::PathBuf;

pub enum LocalReadResult {
    /// 可读副本不足（< 2），无法形成多数投票
    Insufficient { read_count: usize },
    /// 读到 >= 2 个副本，但无多数共识（均不同），怀疑被篡改
    Tampered { read_count: usize },
    /// 多数投票通过，value=(activation_ts, expires_at)
    Success {
        value: (u64, u64),
        read_count: usize,
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
    // 12 nonce + 32 ciphertext(16 plain + 16 GCM tag)
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

/// 多数投票读取本地副本
///
/// 投票表（read_count=N, best_count=B）:
/// - N=0,1       → Insufficient（不足2个副本）
/// - N=2, B=2:0  → Success ✓
/// - N=2, B=1:1  → Tampered ✓（无多数）
/// - N=3, B=3:0  → Success ✓
/// - N=3, B=2:1  → Success ✓（自动修复少数副本）
/// - N=3, B=1:1:1→ Tampered ✓（无多数）

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
    // ✅ MAJOR-B FIX: 提前返回 Insufficient，防止下方 .unwrap() 在 read_count=0 时 panic
    if read_count < 2 {
        return LocalReadResult::Insufficient { read_count };
    }

    // 统计各值出现次数

    let mut counts: Vec<((u64, u64), usize)> = Vec::new();
    for &v in &values {
        if let Some(entry) = counts.iter_mut().find(|(val, _)| *val == v) {
            entry.1 += 1;
        } else {
            counts.push((v, 1));
        }
    }

    // 此时 read_count >= 2，counts 非空，unwrap() 安全
    let (best_val, best_count) = counts.iter().max_by_key(|(_, c)| *c).copied().unwrap();
    if best_count * 2 > read_count {
        // 有多数（>50%），修复少数损坏副本
        if best_count < read_count {
            for slot in 0..3u8 {
                let path = derive_path(hkey, salt, slot);
                let needs_repair = match read_slot(&path, &key) {
                    Some(pair) => pair != best_val,
                    None => true,
                };
                if needs_repair {
                    if let Err(e) = write_slot(&path, &key, best_val.0, best_val.1) {
                        tracing::warn!("[Storage] Replica {} repair failed: {}", slot, e);
                    } else {
                        tracing::info!("[Storage] Replica {} repaired", slot);
                    }
                }
            }
        }

        LocalReadResult::Success {
            value: best_val,
            read_count,
        }
    } else {
        // 无多数（如 1:1 或 1:1:1），真正的篡改
        LocalReadResult::Tampered { read_count }
    }
}

/// 写入所有 3 个副本
pub fn write_all_replicas(hkey: &str, salt: &str, activation: u64, expires: u64) {
    let key = derive_key(hkey, salt);
    for slot in 0..3u8 {
        let path = derive_path(hkey, salt, slot);
        if let Err(e) = write_slot(&path, &key, activation, expires) {
            tracing::warn!("[Storage] Replica {} write failed: {}", slot, e);
        }
    }
}
