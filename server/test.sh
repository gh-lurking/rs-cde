#!/bin/bash
# 开发/测试启动脚本 v2

# ── 依赖 ───────────────────────────────────────────────────────────────────────
# PostgreSQL:
#   docker run -d --name pglic \
#     -e POSTGRES_USER=licenseuser \
#     -e POSTGRES_PASSWORD=secret \
#     -e POSTGRES_DB=licensedb \
#     -p 5432:5432 postgres:16
#
# Redis:
#   docker run -d --name redislic \
#     -p 6379:6379 redis:7 \
#     redis-server --requirepass "redispassword"

# ── 环境变量 ───────────────────────────────────────────────────────────────────
export DATABASE_URL="postgres://licenseuser:secret@localhost:5432/licensedb"
export PG_POOL_MAX_CONN=20
export PG_POOL_MIN_CONN=2

export REDIS_URL="redis://:redispassword@localhost:6379/0"
export REDIS_POOL_SIZE=32
export VERIFY_CACHE_TTL_SECS=30

export ADMIN_TOKEN="your-64-char-random-hex-admin-token-here-00000000000000000000000"
export BIND_ADDR="127.0.0.1:8080"
export SERVER_ID="license-server-v1"        # 必须与客户端 BUILD_SERVER_ID 一致
export TIMESTAMP_WINDOW_SECS=300

# ── 启动服务端 ─────────────────────────────────────────────────────────────────
cargo run --release &
SERVER_PID=$!
sleep 2

# ── 健康检查 ───────────────────────────────────────────────────────────────────
echo "=== Health ==="
curl -s http://localhost:8080/health | jq .

# ── 批量生成 10 个 License Key ────────────────────────────────────────────────
echo "=== Batch Init ==="
curl -s -X POST http://localhost:8080/admin/batch-init \
  -H 'Content-Type: application/json' \
  -d "{"token":"$ADMIN_TOKEN","count":10}" | jq .

# ── 续期（默认不允许对已过期 key）────────────────────────────────────────────
echo "=== Extend (active key) ==="
curl -s -X POST http://localhost:8080/admin/extend \
  -H 'Content-Type: application/json' \
  -d "{"token":"$ADMIN_TOKEN","key_hash":"<key_hash>","extra_days":30}" | jq .

# ── 续期已过期 key（需显式 allow_expired=true）───────────────────────────────
echo "=== Extend (expired key, forced) ==="
curl -s -X POST http://localhost:8080/admin/extend \
  -H 'Content-Type: application/json' \
  -d "{"token":"$ADMIN_TOKEN","key_hash":"<key_hash>","extra_days":365,"allow_expired":true}" | jq .

kill $SERVER_PID

# VERIFY_CACHE_TTL_SECS 设多少合适？
# 客户端校验间隔（network.rs 中的 NET_TIMEOUT_SECS 的调用频率）通常 5~60 分钟。
# TTL=30s 即缓存最多缓存30秒；如果客户端5分钟才验证一次，30s TTL 命中率接近100%。可以根据客户端实际周期调整，一般 15~60s 都合理。  
