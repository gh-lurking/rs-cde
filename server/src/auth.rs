// server/src/auth.rs — 优化版 v2
// ✅ OPT-04 FIX: 移除无意义的 ct_eq(a,a)，添加清晰注释
use subtle::ConstantTimeEq;

pub fn verify_admin_token(provided: &str, expected: &str) -> bool {
    let a = provided.as_bytes();
    let b = expected.as_bytes();

    if a.len() != b.len() {
        // ADMIN_TOKEN 由服务端生成，长度固定（如 64 字符 hex）。
        // 长度不同说明根本不是合法格式，直接拒绝，无需常量时间。
        // 注意：不执行 ct_eq(a,a) 这类无意义操作，避免迷惑代码审查者。
        return false;
    }

    // 长度相同时必须常量时间比较，防止逐字节时序侧信道攻击
    a.ct_eq(b).into()
}
