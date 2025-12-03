# MariaDB CI Dockerfile
# Unlike MySQL, MariaDB does not ship auth_test_plugin.so, so we use the stock image directly.
# Cleartext plugin tests will be skipped when running against MariaDB.

ARG MARIADB_VERSION=10.11
FROM mariadb:${MARIADB_VERSION}
