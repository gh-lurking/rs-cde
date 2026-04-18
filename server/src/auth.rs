// server/src/auth.rs — 无变化（原实现正确）
// 恒定时间 token 比较，防时序侧信道攻击

pub fn verify_admin_token(provided: &str, expected: &str) -> bool {
    let a = provided.as_bytes();
    let b = expected.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
