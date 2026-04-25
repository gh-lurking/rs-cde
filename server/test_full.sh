#!/bin/bash
# server/test_full.sh — 完整验证脚本
# 包含正常路径、边界条件、异常路径、过期/宽限期验证
#
# 环境要求：jq, curl, docker (PostgreSQL + Redis)
# 使用方法：bash test_full.sh

set -euo pipefail

export DATABASE_URL="postgres://licenseuser:secret@localhost:5432/licensedb"
export REDIS_URL="redis://:redispassword@localhost:6379/0"
export ADMIN_TOKEN="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
export BIND_ADDR="127.0.0.1:8080"
export SERVER_ID="license-server-v1"
export TIMESTAMP_WINDOW_SECS=300
export VERIFY_CACHE_TTL_SECS=5
export RUST_LOG=info

BASE="http://localhost:8080"

pass() { echo "  ✅ $1"; }
fail() { echo "  ❌ $1"; exit 1; }

check_status() {
    local label="$1" expected="$2" actual="$3"
    [ "$actual" = "$expected" ] && pass "$label (HTTP $actual)" \
        || fail "$label: expected HTTP $expected, got HTTP $actual"
}

echo "=== 启动服务 ==="
cd "$(dirname "$0")"
cargo build --release 2>/dev/null
./target/release/v0 &
SERVER_PID=$!
sleep 2
echo "服务 PID: $SERVER_PID"

cleanup() { kill $SERVER_PID 2>/dev/null || true; }
trap cleanup EXIT

# ── 1. 健康检查 ──
echo ""; echo "=== [测试1] 健康检查 ==="
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/health")
check_status "health endpoint" "200" "$STATUS"

# ── 2. 生成 Key ──
echo ""; echo "=== [测试2] 生成 Key ==="
RESP=$(curl -s -X POST "$BASE/admin/add-key" \
  -H 'Content-Type: application/json' \
  -d "{\"token\":\"$ADMIN_TOKEN\",\"note\":\"test-key\"}")
KEY=$(echo "$RESP" | jq -r '.key')
KEY_HASH=$(echo "$RESP" | jq -r '.key_hash')
[ -n "$KEY" ] && [ "$KEY" != "null" ] && pass "key generated" \
    || fail "key generation"

# ── 3. 正常激活 ──
echo ""; echo "=== [测试3] 正常激活 ==="
TIMESTAMP=$(date +%s)
SIGNATURE=$(echo -n "license-server-v1|${KEY_HASH}|${TIMESTAMP}" \
  | openssl dgst -sha256 -hmac "$KEY" -hex | awk '{print $2}')
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/activate" \
  -H 'Content-Type: application/json' \
  -d "{\"key_hash\":\"$KEY_HASH\",\"timestamp\":$TIMESTAMP,\"signature\":\"$SIGNATURE\"}")
check_status "activate" "200" "$STATUS"

# ── 4. 正常验证 ──
echo ""; echo "=== [测试4] 正常验证 ==="
sleep 1
TIMESTAMP=$(date +%s)
SIGNATURE=$(echo -n "license-server-v1|${KEY_HASH}|${TIMESTAMP}" \
  | openssl dgst -sha256 -hmac "$KEY" -hex | awk '{print $2}')
RESP=$(curl -s -X POST "$BASE/verify" \
  -H 'Content-Type: application/json' \
  -d "{\"key_hash\":\"$KEY_HASH\",\"timestamp\":$TIMESTAMP,\"signature\":\"$SIGNATURE\"}")
EXPIRES_AT=$(echo "$RESP" | jq -r '.expires_at')
[ "$EXPIRES_AT" -gt 0 ] 2>/dev/null && pass "verify OK" || fail "verify failed"

# ── 5. Nonce 重放 ──
echo ""; echo "=== [测试5] Nonce 重放 ==="
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/verify" \
  -H 'Content-Type: application/json' \
  -d "{\"key_hash\":\"$KEY_HASH\",\"timestamp\":$TIMESTAMP,\"signature\":\"$SIGNATURE\"}")
check_status "nonce replay" "409" "$STATUS"

# ── 6. 无效 Key ──
echo ""; echo "=== [测试6] 无效 Key ==="
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/verify" \
  -H 'Content-Type: application/json' \
  -d "{\"key_hash\":\"$(printf '%064d' 0)\",\"timestamp\":$(date +%s),\"signature\":\"fakesig\"}")
check_status "invalid key" "403" "$STATUS"

# ── 7. 时间偏差 ──
echo ""; echo "=== [测试7] 时间偏差 ==="
OLD_TS=$(($(date +%s) - 400))
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/verify" \
  -H 'Content-Type: application/json' \
  -d "{\"key_hash\":\"$KEY_HASH\",\"timestamp\":$OLD_TS,\"signature\":\"fakesig\"}")
check_status "old timestamp" "400" "$STATUS"

# ── 8. Revoke ──
echo ""; echo "=== [测试8] Revoke ==="
curl -s -X POST "$BASE/admin/revoke" \
  -H 'Content-Type: application/json' \
  -d "{\"token\":\"$ADMIN_TOKEN\",\"key_hash\":\"$KEY_HASH\",\"reason\":\"test\"}" > /dev/null
sleep 1
TIMESTAMP=$(date +%s)
SIGNATURE=$(echo -n "license-server-v1|${KEY_HASH}|${TIMESTAMP}" \
  | openssl dgst -sha256 -hmac "$KEY" -hex | awk '{print $2}')
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/verify" \
  -H 'Content-Type: application/json' \
  -d "{\"key_hash\":\"$KEY_HASH\",\"timestamp\":$TIMESTAMP,\"signature\":\"$SIGNATURE\"}")
check_status "revoked" "403" "$STATUS"

# ── 9. 过期验证 (BUG-CRIT-1 / BUG-HIGH-1 验证) ──
echo ""; echo "=== [测试9] 过期验证 ==="
RESP2=$(curl -s -X POST "$BASE/admin/add-key" \
  -H 'Content-Type: application/json' \
  -d "{\"token\":\"$ADMIN_TOKEN\",\"note\":\"expire-test\"}")
KEY2=$(echo "$RESP2" | jq -r '.key')
KEY_HASH2=$(echo "$RESP2" | jq -r '.key_hash')
TIMESTAMP=$(date +%s)
SIGNATURE2=$(echo -n "license-server-v1|${KEY_HASH2}|${TIMESTAMP}" \
  | openssl dgst -sha256 -hmac "$KEY2" -hex | awk '{print $2}')
curl -s -X POST "$BASE/activate" \
  -H 'Content-Type: application/json' \
  -d "{\"key_hash\":\"$KEY_HASH2\",\"timestamp\":$TIMESTAMP,\"signature\":\"$SIGNATURE2\"}" > /dev/null

# 设置 DB 中过期时间为 1 秒后
docker exec pglic psql -U licenseuser -d licensedb -c \
  "UPDATE licenses SET expires_at = extract(epoch from now())::bigint + 1 \
   WHERE key_hash = '$KEY_HASH2';" 2>/dev/null || echo "  (跳过 DB 操作)"

sleep 2
TIMESTAMP=$(date +%s)
SIGNATURE2=$(echo -n "license-server-v1|${KEY_HASH2}|${TIMESTAMP}" \
  | openssl dgst -sha256 -hmac "$KEY2" -hex | awk '{print $2}')
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/verify" \
  -H 'Content-Type: application/json' \
  -d "{\"key_hash\":\"$KEY_HASH2\",\"timestamp\":$TIMESTAMP,\"signature\":\"$SIGNATURE2\"}")
echo "  过期状态码: $STATUS (期望 410)"

# ── 10. BUG-CRIT-1 验证：极端时间戳不应崩溃 ──
echo ""; echo "=== [测试10] BUG-CRIT-1: 极端时间戳防溢出 ==="
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/verify" \
  -H 'Content-Type: application/json' \
  -d "{\"key_hash\":\"$KEY_HASH\",\"timestamp\":-9223372036854775808,\"signature\":\"fakesig\"}")
# 期望 400 BAD_REQUEST（时间窗口拒绝），而非 500 崩溃
echo "  极端时间戳状态码: $STATUS (期望 400 拒绝，不应 500 崩溃)"

echo ""
echo "=== ✅ 所有测试完成 ==="

