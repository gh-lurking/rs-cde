// client/src/storage.rs — 优化版 v9
//
// ✅ OPT-3 FIX: LocalReadResult::Success 新增 repair_failed: bool
// ✅ MAJOR-A FIX: N=2:0 误判修复（已正确 best_count*2 > read_count）
// ✅ MAJOR-B FIX: best_val 值域合理性验证（防止被篡改的大值通过投票）
use aes_gcm::{
    Aes128Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use hkdf::Hkdf;
use sha2::Sha256;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// 本地副本读取结果
pub enum LocalReadResult {
    /// 可用副本数 < 2
    Insufficient { read_count: usize },
    /// 2+ 副本读取成功，但无法形成多数（1:1 分裂或均不一致）
    Tampered { read_count: usize },
    /// 多数票成功
    Success {
        value: (u64, u64), // (activation_ts, expires_at)
        read_count: usize,
        repair_failed: bool, // ✅ OPT-3: 副本修复是否失败
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
    // 12 nonce + 32 ciphertext (16 plain + 16 GCM tag)
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

/// 写入3个副本（激活/验证成功后调用）
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
///
/// 仲裁规则（read_count=N, best_count=B）:
/// - N=0,1     → Insufficient
/// - N=2, B=2  → Success ✓
/// - N=2, B=1  → Tampered ✓
/// - N=3, B=3  → Success ✓
/// - N=3, B=2  → Success ✓（自动修复少数派，repair_failed 标记修复状态）
/// - N=3, B=1:1:1 → Tampered ✓
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

    // ✅ MAJOR-A FIX: 先检查 read_count < 2 → Insufficient
    if read_count < 2 {
        return LocalReadResult::Insufficient { read_count };
    }

    // 投票仲裁：统计各值出现次数
    let mut counts: Vec<((u64, u64), usize)> = Vec::new();
    for &v in &values {
        if let Some(entry) = counts.iter_mut().find(|(val, _)| *val == v) {
            entry.1 += 1;
        } else {
            counts.push((v, 1));
        }
    }

    // read_count >= 2，counts 非空，unwrap 安全
    let (best_val, best_count) = counts.iter().max_by_key(|(_, c)| *c).copied().unwrap();

    if best_count * 2 <= read_count {
        // 无法形成多数（如 1:1 或 1:1:1）
        return LocalReadResult::Tampered { read_count };
    }

    // ✅ MAJOR-B FIX: 对 best_val 做值域合理性验证
    // 防止攻击者篡改 2/3 副本为更大的 expires_at
    let (act_ts, exp_ts) = best_val;
    let now_u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // activation_ts 不应在未来（超过 5 分钟）
    if act_ts > now_u64 + 300 {
        tracing::warn!(
            "[Storage] Sanity check failed: activation_ts({}) in future (now={})",
            act_ts,
            now_u64
        );
        return LocalReadResult::Tampered { read_count };
    }

    // expires_at 必须 > activation_ts，且差值 <= 10年
    const MAX_LICENSE_PERIOD: u64 = 10 * 365 * 86400;
    if exp_ts <= act_ts || (exp_ts - act_ts) > MAX_LICENSE_PERIOD {
        tracing::warn!(
            "[Storage] Sanity check failed: act={} exp={} diff={}",
            act_ts,
            exp_ts,
            exp_ts.saturating_sub(act_ts)
        );
        return LocalReadResult::Tampered { read_count };
    }

    // 有多数票，修复少数/缺失副本
    let mut repair_failed = false;
    if best_count < read_count || read_count < 3 {
        for slot in 0..3u8 {
            let path = derive_path(hkey, salt, slot);
            let needs_repair = match read_slot(&path, &key) {
                Some(pair) => pair != best_val,
                None => true,
            };
            if needs_repair {
                if let Err(e) = write_slot(&path, &key, best_val.0, best_val.1) {
                    tracing::warn!("[Storage] Replica {} repair failed: {}", slot, e);
                    repair_failed = true; // ✅ OPT-3: 记录修复失败
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
