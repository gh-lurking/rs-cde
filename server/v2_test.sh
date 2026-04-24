#!/bin/bash
# server/test_full_v2.sh — 验证 BUG-EXP-1/2 修复的额外测试
# 在原 test_full.sh 基础上增加以下场景

set -euo pipefail
BASE="http://localhost:8080"
pass() { echo "  ✅ $1"; }
fail() { echo "  ❌ $1"; exit 1; }

# ─────────────────────────────────────────────────────────────────
# 场景 A：临界过期时 nonce 不被消耗（BUG-EXP-1/2 验证）
# ─────────────────────────────────────────────────────────────────
echo "=== [验证A] 临界过期：过期请求不消耗 nonce ==="

# 1. 生成并激活 key
RESP=$(curl -s -X POST "$BASE/admin/add-key" \
  -H 'Content-Type: application/json' \
  -d '{"token":"'$ADMIN_TOKEN'","note":"expire-boundary-test"}')
KEY=$(echo "$RESP" | jq -r '.key')
KEY_HASH=$(echo "$RESP" | jq -r '.key_hash')

TIMESTAMP=$(date +%s)
SIG=$(echo -n "license-server-v1|$KEY_HASH|$TIMESTAMP" \
  | openssl dgst -sha256 -hmac "$KEY" -hex | awk '{print $2}')
curl -s -X POST "$BASE/activate" \
  -H 'Content-Type: application/json' \
  -d '{"key_hash":"'$KEY_HASH'","timestamp":'$TIMESTAMP',"signature":"'$SIG'"}' > /dev/null

# 2. 将 key 设置为 1 秒后过期
docker exec pglic psql -U licenseuser -d licensedb -c \
  "UPDATE licenses SET expires_at = extract(epoch from now())::bigint + 1 \
   WHERE key_hash = '$KEY_HASH';" 2>/dev/null

# 3. 等 key 过期
sleep 2

# 4. 发送过期请求，记录使用的 timestamp
TS_EXPIRED=$(date +%s)
SIG_EXPIRED=$(echo -n "license-server-v1|$KEY_HASH|$TS_EXPIRED" \
  | openssl dgst -sha256 -hmac "$KEY" -hex | awk '{print $2}')

STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/verify" \
  -H 'Content-Type: application/json' \
  -d '{"key_hash":"'$KEY_HASH'","timestamp":'$TS_EXPIRED',"signature":"'$SIG_EXPIRED'"}')
[ "$STATUS" = "410" ] && pass "过期请求返回 410 GONE" || fail "期望 410，实际 $STATUS"

# 5. 用同一 timestamp 重试（验证 nonce 未被消耗）
STATUS2=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/verify" \
  -H 'Content-Type: application/json' \
  -d '{"key_hash":"'$KEY_HASH'","timestamp":'$TS_EXPIRED',"signature":"'$SIG_EXPIRED'"}')
[ "$STATUS2" = "410" ] && pass "nonce 未被过期请求消耗（重试仍 410）" \
  || fail "BUG-EXP-1 未修复：期望 410，实际 $STATUS2（可能是 409）"

# ─────────────────────────────────────────────────────────────────
# 场景 B：有效密钥正常验证（正常路径）
# ─────────────────────────────────────────────────────────────────
echo "=== [验证B] 正常路径：有效密钥验证通过 ==="

RESP2=$(curl -s -X POST "$BASE/admin/add-key" \
  -H 'Content-Type: application/json' \
  -d '{"token":"'$ADMIN_TOKEN'","note":"valid-test"}')
KEY2=$(echo "$RESP2" | jq -r '.key')
KEY_HASH2=$(echo "$RESP2" | jq -r '.key_hash')

TS=$(date +%s)
SIG2=$(echo -n "license-server-v1|$KEY_HASH2|$TS" \
  | openssl dgst -sha256 -hmac "$KEY2" -hex | awk '{print $2}')
curl -s -X POST "$BASE/activate" \
  -H 'Content-Type: application/json' \
  -d '{"key_hash":"'$KEY_HASH2'","timestamp":'$TS',"signature":"'$SIG2'"}' > /dev/null

sleep 1
TS2=$(date +%s)
SIG3=$(echo -n "license-server-v1|$KEY_HASH2|$TS2" \
  | openssl dgst -sha256 -hmac "$KEY2" -hex | awk '{print $2}')
STATUS3=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/verify" \
  -H 'Content-Type: application/json' \
  -d '{"key_hash":"'$KEY_HASH2'","timestamp":'$TS2',"signature":"'$SIG3'"}')
[ "$STATUS3" = "200" ] && pass "有效密钥验证通过 (200)" || fail "期望 200，实际 $STATUS3"

# ─────────────────────────────────────────────────────────────────
# 场景 C：缓存命中时 nonce 正常去重（边界条件）
# ─────────────────────────────────────────────────────────────────
echo "=== [验证C] 缓存命中：nonce 去重正常工作 ==="
STATUS4=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/verify" \
  -H 'Content-Type: application/json' \
  -d '{"key_hash":"'$KEY_HASH2'","timestamp":'$TS2',"signature":"'$SIG3'"}')
[ "$STATUS4" = "409" ] && pass "nonce 重放被拒绝 (409)" || fail "期望 409，实际 $STATUS4"

echo "=== ✅ BUG-EXP-1/2 修复验证完成 ==="