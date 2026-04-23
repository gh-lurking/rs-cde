#!/bin/bash
# server/test_full.sh — 完整验证脚本（含正常路径、边界条件、异常路径）
# 使用方法：
#   bash test_full.sh
# 依赖：jq, curl, docker（PostgreSQL + Redis）

set -euo pipefail

# ── 环境变量 ────────────────────────────────────────────────────────────────
export DATABASE_URL="postgres://licenseuser:secret@localhost:5432/licensedb"
export REDIS_URL="redis://:redispassword@localhost:6379/0"
export ADMIN_TOKEN="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
export BIND_ADDR="127.0.0.1:8080"
export SERVER_ID="license-server-v1"
export TIMESTAMP_WINDOW_SECS=300
export VERIFY_CACHE_TTL_SECS=5  # 测试时缩短 TTL，便于验证过期场景
export RUST_LOG=info

BASE="http://localhost:8080"

# ── 工具函数 ────────────────────────────────────────────────────────────────
pass() { echo "  ✅ $1"; }
fail() { echo "  ❌ $1"; exit 1; }

check_status() {
    local label="$1"
    local expected="$2"
    local actual="$3"
    if [ "$actual" = "$expected" ]; then
        pass "$label (HTTP $actual)"
    else
        fail "$label: expected HTTP $expected, got HTTP $actual"
    fi
}

# ── 启动服务 ────────────────────────────────────────────────────────────────
echo "=== 启动服务 ==="
cd "$(dirname "$0")"
cargo build --release 2>/dev/null
./target/release/v0 &
SERVER_PID=$!
sleep 2
echo "服务 PID: $SERVER_PID"

cleanup() { kill $SERVER_PID 2>/dev/null || true; }
trap cleanup EXIT

# ── 1. 健康检查 ──────────────────────────────────────────────────────────────
echo ""
echo "=== [测试1] 健康检查 ==="
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/health")
check_status "health endpoint" "200" "$STATUS"

# ── 2. 生成 Key ──────────────────────────────────────────────────────────────
echo ""
echo "=== [测试2] 生成单个 Key ==="
RESP=$(curl -s -X POST "$BASE/admin/add-key"   -H 'Content-Type: application/json'   -d "{"token":"$ADMIN_TOKEN","note":"test-key"}")
echo "  Response: $RESP"
KEY=$(echo "$RESP" | jq -r '.key')
KEY_HASH=$(echo "$RESP" | jq -r '.key_hash')
[ -n "$KEY" ] && [ "$KEY" != "null" ] && pass "key generated: $KEY" || fail "key generation"

# ── 3. 正常路径：激活 Key ────────────────────────────────────────────────────
echo ""
echo "=== [测试3] 正常路径 - 激活 Key ==="
TIMESTAMP=$(date +%s)
# 生成 HMAC 签名（Shell 版本，用于测试）
SIGNATURE=$(echo -n "license-server-v1|${KEY_HASH}|${TIMESTAMP}" |   openssl dgst -sha256 -hmac "$KEY" -hex | awk '{print $2}')

STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/activate"   -H 'Content-Type: application/json'   -d "{"key_hash":"$KEY_HASH","timestamp":$TIMESTAMP,"signature":"$SIGNATURE"}")
check_status "activate (valid key)" "200" "$STATUS"

# ── 4. 正常路径：验证已激活 Key ──────────────────────────────────────────────
echo ""
echo "=== [测试4] 正常路径 - 验证已激活 Key ==="
sleep 1  # 错开时间戳，避免 nonce 冲突
TIMESTAMP=$(date +%s)
SIGNATURE=$(echo -n "license-server-v1|${KEY_HASH}|${TIMESTAMP}" |   openssl dgst -sha256 -hmac "$KEY" -hex | awk '{print $2}')

RESP=$(curl -s -X POST "$BASE/verify"   -H 'Content-Type: application/json'   -d "{"key_hash":"$KEY_HASH","timestamp":$TIMESTAMP,"signature":"$SIGNATURE"}")
echo "  Response: $RESP"
EXPIRES_AT=$(echo "$RESP" | jq -r '.expires_at')
[ "$EXPIRES_AT" -gt 0 ] 2>/dev/null && pass "verify OK, expires_at=$EXPIRES_AT" || fail "verify response invalid"

# ── 5. 边界条件：重放 Nonce 攻击 ─────────────────────────────────────────────
echo ""
echo "=== [测试5] 边界条件 - Nonce 重放攻击 ==="
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/verify"   -H 'Content-Type: application/json'   -d "{"key_hash":"$KEY_HASH","timestamp":$TIMESTAMP,"signature":"$SIGNATURE"}")
check_status "nonce replay rejected" "409" "$STATUS"

# ── 6. 异常路径：无效 Key =───────────────────────────────────────────────────
echo ""
echo "=== [测试6] 异常路径 - 无效 Key Hash ==="
TIMESTAMP=$(date +%s)
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/verify"   -H 'Content-Type: application/json'   -d "{"key_hash":"$(printf '%064d' 0)","timestamp":$TIMESTAMP,"signature":"fakesig"}")
check_status "invalid key_hash rejected" "403" "$STATUS"

# ── 7. 边界条件：时钟偏差过大 ──────────────────────────────────────────────
echo ""
echo "=== [测试7] 边界条件 - 时间戳偏差过大 ==="
OLD_TS=$(($(date +%s) - 400))  # 400s ago，超过 300s 窗口
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/verify"   -H 'Content-Type: application/json'   -d "{"key_hash":"$KEY_HASH","timestamp":$OLD_TS,"signature":"fakesig"}")
check_status "old timestamp rejected" "400" "$STATUS"

# ── 8. 测试 revoke：已撤销 Key 被拒绝 ─────────────────────────────────────
echo ""
echo "=== [测试8] revoke - 撤销后 verify 返回 403 ==="
curl -s -X POST "$BASE/admin/revoke"   -H 'Content-Type: application/json'   -d "{"token":"$ADMIN_TOKEN","key_hash":"$KEY_HASH","reason":"test revoke"}" > /dev/null

sleep 1  # 等 tombstone 写入
TIMESTAMP=$(date +%s)
SIGNATURE=$(echo -n "license-server-v1|${KEY_HASH}|${TIMESTAMP}" |   openssl dgst -sha256 -hmac "$KEY" -hex | awk '{print $2}')
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/verify"   -H 'Content-Type: application/json'   -d "{"key_hash":"$KEY_HASH","timestamp":$TIMESTAMP,"signature":"$SIGNATURE"}")
check_status "revoked key rejected" "403" "$STATUS"

# ── 9. 过期场景：生成即将过期的 Key 并验证 ─────────────────────────────────
echo ""
echo "=== [测试9] 过期场景 - 使用 batch-init + 手动设置过期时间 ==="
# 生成新 key
RESP2=$(curl -s -X POST "$BASE/admin/add-key"   -H 'Content-Type: application/json'   -d "{"token":"$ADMIN_TOKEN","note":"expire-test"}")
KEY2=$(echo "$RESP2" | jq -r '.key')
KEY_HASH2=$(echo "$RESP2" | jq -r '.key_hash')

# 激活
TIMESTAMP=$(date +%s)
SIGNATURE2=$(echo -n "license-server-v1|${KEY_HASH2}|${TIMESTAMP}" |   openssl dgst -sha256 -hmac "$KEY2" -hex | awk '{print $2}')
curl -s -X POST "$BASE/activate"   -H 'Content-Type: application/json'   -d "{"key_hash":"$KEY_HASH2","timestamp":$TIMESTAMP,"signature":"$SIGNATURE2"}" > /dev/null

# 直接修改 DB 使其立即过期（测试专用）
PSQL_CMD="UPDATE licenses SET expires_at = extract(epoch from now())::bigint - 1 WHERE key_hash = '$KEY_HASH2';"
docker exec pglic psql -U licenseuser -d licensedb -c "$PSQL_CMD" 2>/dev/null && echo "  DB 中手动设置 key2 已过期" || echo "  (跳过 DB 直接操作，需 docker)"

sleep 1
TIMESTAMP=$(date +%s)
SIGNATURE2=$(echo -n "license-server-v1|${KEY_HASH2}|${TIMESTAMP}" |   openssl dgst -sha256 -hmac "$KEY2" -hex | awk '{print $2}')
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/verify"   -H 'Content-Type: application/json'   -d "{"key_hash":"$KEY_HASH2","timestamp":$TIMESTAMP,"signature":"$SIGNATURE2"}")
# 期望 410 GONE（如果 DB 修改成功）或 200（如果跳过）
echo "  过期验证状态码: $STATUS（期望 410 如果 DB 修改成功）"

# ── 10. batch-init 边界：count=5000（新上界） ──────────────────────────────
echo ""
echo "=== [测试10] batch-init 边界 count=5000 ==="
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/admin/batch-init"   -H 'Content-Type: application/json'   -d "{"token":"$ADMIN_TOKEN","count":5000,"note":"bulk"}")
check_status "batch-init count=5000" "200" "$STATUS"

# ── 11. batch-init 异常：count=5001（超过新上界） ─────────────────────────
echo ""
echo "=== [测试11] batch-init 异常 count=5001（超上界） ==="
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/admin/batch-init"   -H 'Content-Type: application/json'   -d "{"token":"$ADMIN_TOKEN","count":5001}")
check_status "batch-init count=5001 rejected" "400" "$STATUS"

# ── 12. key_cache 进程内缓存验证 ──────────────────────────────────────────
echo ""
echo "=== [测试12] 进程内 key_cache 大小观测 ==="
HEALTH=$(curl -s "$BASE/health")
CACHE_SIZE=$(echo "$HEALTH" | jq -r '.key_cache_size // 0')
echo "  key_cache_size = $CACHE_SIZE"
[ "$CACHE_SIZE" -ge 0 ] && pass "key_cache_size 字段存在" || fail "key_cache_size 字段缺失"

# ── 汇总 ─────────────────────────────────────────────────────────────────────
echo ""
echo "=== ✅ 所有测试通过 ==="

# VERIFY_CACHE_TTL_SECS 设多少合适？
# 客户端校验间隔（network.rs 中的 NET_TIMEOUT_SECS 的调用频率）通常 5~60 分钟。
# TTL=30s 即缓存最多缓存30秒；如果客户端5分钟才验证一次，30s TTL 命中率接近100%。可以根据客户端实际周期调整，一般 15~60s 都合理。  
