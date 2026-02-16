#!/bin/bash
# Install caching_sha2_password plugin and create test user for MariaDB 12.1+
# The caching_sha2_password plugin is only available in MariaDB 12.1+ Community Server

set -e

# Get MariaDB major version (e.g., "12" from "mariadb from 12.1.2-MariaDB")
MAJOR_VERSION=$(mariadb --version | sed -n 's/.*from \([0-9]*\)\..*/\1/p')

if [[ -n "$MAJOR_VERSION" ]] && [[ "$MAJOR_VERSION" -ge 12 ]]; then
    echo "MariaDB $MAJOR_VERSION detected, installing caching_sha2_password plugin..."

    # Unset MYSQL_HOST to force socket connection via localhost
    # The plugin requires RSA keys for non-TLS TCP connections
    unset MYSQL_HOST
    SOCKET="${SOCKET:-/run/mysqld/mysqld.sock}"

    # Install plugin first
    mariadb -u root --socket="$SOCKET" -e "INSTALL PLUGIN IF NOT EXISTS caching_sha2_password SONAME 'auth_mysql_sha2.so';"

    # Create user in separate connection (plugin may reset TCP connections)
    mariadb -u root --socket="$SOCKET" <<-EOSQL
        -- Create caching_sha2_password test user using MariaDB syntax
        CREATE USER IF NOT EXISTS 'caching_sha2'@'%';
        GRANT ALL PRIVILEGES ON test.* TO 'caching_sha2'@'%';
        ALTER USER 'caching_sha2'@'%' IDENTIFIED VIA caching_sha2_password USING PASSWORD('password');
EOSQL

    echo "caching_sha2_password plugin installed and test user created."
else
    echo "MariaDB $MAJOR_VERSION detected, skipping caching_sha2_password (requires 12.1+)."
fi
