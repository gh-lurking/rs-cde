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
