// server/src/auth.rs — 管理员 Token 校验（恒定时间比较，防时序攻击）
// 此文件原来就是正确的，无需修改

/// 使用恒定时间字节比较，防止时序侧信道攻击
pub fn verify_admin_token(provided: &str, expected: &str) -> bool {
    let a = provided.as_bytes();
    let b = expected.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    // 恒定时间比较：即使长度相等，也不短路
    // 防止攻击者通过响应时间差逐字符猜测 token
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
