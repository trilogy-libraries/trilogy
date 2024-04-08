ARG MYSQL_VERSION

FROM mysql:${MYSQL_VERSION}-debian
# Make all apt-get commands non-interactive. Setting this as an ARG will apply to the entire
# build phase, but not leak into the final image and run phase.
ARG DEBIAN_FRONTEND=noninteractive

# MySQL 5.7 has been EOL'd and is no longer being built by the official mysql docker maintainers:
# https://github.com/docker-library/mysql/pull/1019
# Copy the gpg key from the latest MySQL image.
COPY --from=mysql:8.0-debian /etc/apt/keyrings/mysql.gpg /etc/apt/keyrings/mysql.gpg

# Install the MySQL test package so that we can get test plugins.
# https://github.com/docker-library/mysql/issues/1040
RUN set -eux \
    # Install MySQL test package.
    && apt-get update \
    && apt-get install --yes mysql-community-test

# This is the final stage inwhich we copy the plugins from the test stage. Doing it this way allows
# us to not have to install the test package in the final image since we only need the plugins.
FROM mysql:${MYSQL_VERSION}-debian
COPY --from=0 /usr/lib/mysql/plugin/ /usr/lib/mysql/plugin/
