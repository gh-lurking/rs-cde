#!/bin/bash

export DB_PATH="`pwd`/db/licenses.db"
export ADMIN_TOKEN="your-very-long-random-admin-token-32chars+"
export BIND_ADDR="127.0.0.1:1000"
`pwd`/target/release/v0