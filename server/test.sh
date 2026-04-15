#!/bin/bash
# 启动脚本（开发/测试用）
#
# 需要提前准备 PostgreSQL 实例：
#   docker run -d --name pglic \
#     -e POSTGRES_USER=licenseuser \
#     -e POSTGRES_PASSWORD=secret \
#     -e POSTGRES_DB=licensedb \
#     -p 5432:5432 postgres:16

export DATABASE_URL="postgres://licenseuser:secret@localhost:5432/licensedb"
export ADMIN_TOKEN="your-very-long-random-admin-token-32chars+"
export BIND_ADDR="127.0.0.1:8080"
`pwd`/target/release/v0

# ─── 测试用 curl 命令 ──────────────────────────────────────────────────────────

# 1. 健康检查
# curl http://127.0.0.1:8080/health

# 2. 管理员预置一个 License Key（服务端自动生成 HKEY）
# curl -s -X POST http://127.0.0.1:8080/admin/add-key \
#   -H "Content-Type: application/json" \
#   -d '{"token":"your-very-long-random-admin-token-32chars+","valid_days":365,"note":"batch-A"}'

# 3. 管理员预置一个指定明文 Key
# curl -s -X POST http://127.0.0.1:8080/admin/add-key \
#   -H "Content-Type: application/json" \
#   -d '{"token":"your-very-long-random-admin-token-32chars+","key":"HKEY-AAAA-1111-XXXX","valid_days":180}'

# 4. 列出所有 License
# curl "http://127.0.0.1:8080/admin/licenses?token=your-very-long-random-admin-token-32chars+"
