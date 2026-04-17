#!/bin/bash
#!/bin/bash
# 启动脚本（开发/测试用）
#
# 依赖准备：
#
# 1. PostgreSQL
#   docker run -d --name pglic \\
#     -e POSTGRES_USER=licenseuser \\
#     -e POSTGRES_PASSWORD=secret \\
#     -e POSTGRES_DB=licensedb \\
#     -p 5432:5432 postgres:16
#
# ✅ 2. Redis（新增）
#   docker run -d --name redislic \\
#     -p 6379:6379 redis:7 \\
#     redis-server --requirepass "redispassword"

# ── PostgreSQL ───────────────────────────────────────────────────────────────
export DATABASE_URL="postgres://licenseuser:secret@localhost:5432/licensedb"
# ── PostgreSQL 连接池参数（可选，有默认值）──────────────────────────────────
export PG_POOL_MAX_CONN=20   # 最大连接数（默认 20）
export PG_POOL_MIN_CONN=2    # 最小保活连接（默认 2）
# ── ✅ Redis（新增）─────────────────────────────────────────────────────────
export REDIS_URL="redis://:redispassword@localhost:6379/0"
export REDIS_POOL_SIZE=32          # Redis 连接池最大连接数（默认 32）
export VERIFY_CACHE_TTL_SECS=300   # /verify 缓存 TTL 秒数（默认 30）

# ── 管理员 Token + 绑定地址 ──────────────────────────────────────────────────
export ADMIN_TOKEN="your-very-long-random-admin-token-32chars+"
export BIND_ADDR="127.0.0.1:8080"
`pwd`/target/release/v0


# 健康检查
curl http://localhost:8080/health

# 批量生成 License Key
curl -X POST http://localhost:8080/admin/batch-init \
  -H 'Content-Type: application/json' \
  -d '{"token":"your-admin-token","count":10}'

# 激活 Key（客户端调用）
curl -X POST http://localhost:8080/activate \
  -H 'Content-Type: application/json' \
  -d '{"key_hash":"<sha256_of_key>","timestamp":1700000000,"signature":"..."}'

# 校验（第一次会写 Redis，第二次直接命中缓存）
curl -X POST http://localhost:8080/verify \
  -H 'Content-Type: application/json' \
  -d '{"key_hash":"<sha256_of_key>","timestamp":1700000000,"signature":"..."}'

# VERIFY_CACHE_TTL_SECS 设多少合适？
# 客户端校验间隔（network.rs 中的 NET_TIMEOUT_SECS 的调用频率）通常 5~60 分钟。
# TTL=30s 即缓存最多缓存30秒；如果客户端5分钟才验证一次，30s TTL 命中率接近100%。可以根据客户端实际周期调整，一般 15~60s 都合理。  
