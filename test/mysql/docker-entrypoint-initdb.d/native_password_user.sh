#!/usr/bin/env bash

# Create native password user only if MySQL version < 9.
# MySQL 9.x completely removed the mysql_native_password plugin.

set -euo pipefail

# Get MySQL major version (use -h localhost to avoid MYSQL_HOST env var)
MYSQL_MAJOR_VERSION=$(mysql -h localhost -uroot -N -e "SELECT SUBSTRING_INDEX(VERSION(), '.', 1)")

if [[ "$MYSQL_MAJOR_VERSION" -lt 9 ]]; then
    echo "MySQL $MYSQL_MAJOR_VERSION.x detected, creating native password user..."
    mysql -h localhost -uroot <<EOF
CREATE USER 'native'@'%';
GRANT ALL PRIVILEGES ON test.* TO 'native'@'%';
ALTER USER 'native'@'%' IDENTIFIED WITH mysql_native_password BY 'password';
EOF
    echo "native user created successfully"
else
    echo "MySQL $MYSQL_MAJOR_VERSION.x detected, mysql_native_password not available, skipping native user creation"
fi
