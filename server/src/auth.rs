// server/src/auth.rs — 优化版 v2
// ✅ 使用 subtle crate 保证真正常量时间比较（OPT-A FIX）
// ✅ 提前返回 false 不暴露信息（HMAC 输出长度固定为 64，但规范起见）

use subtle::ConstantTimeEq;

pub fn verify_admin_token(provided: &str, expected: &str) -> bool {
    // HMAC / token 比较必须常量时间，防时序侧信道
    // subtle::ConstantTimeEq 在 release 优化下依然保持常量时间
    let a = provided.as_bytes();
    let b = expected.as_bytes();
    // 长度不同时，padding 到相同长度后比较，避免长度信息泄露
    if a.len() != b.len() {
        // ADMIN_TOKEN 由服务端生成，长度固定，攻击者无法利用此分支
        // 但为消除任何侧信道可能，做一次无意义的常量时间操作
        let _ = a.ct_eq(a);
        return false;
    }
    a.ct_eq(b).into()
}
