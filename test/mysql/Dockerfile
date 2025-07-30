ARG DISTRIBUTION=debian:bookworm
FROM ${DISTRIBUTION}

ARG MYSQL_VERSION

# Make all apt-get commands non-interactive. Setting this as an ARG will apply to the entire
# build phase, but not leak into the final image and run phase.
ARG DEBIAN_FRONTEND=noninteractive

# Install MySQL from apt repositories.
RUN set -eux \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        wget \
        gnupg \
        lsb-release \
    && echo "deb https://repo.mysql.com/apt/debian/ buster mysql-${MYSQL_VERSION}" > /etc/apt/sources.list.d/mysql.list \
    && apt-key adv --keyserver keyserver.ubuntu.com --recv-keys A8D3785C 3A79BD29 \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        mysql-server \
        mysql-client

# Copy plugins to expected location.
RUN mkdir -p /usr/lib/mysql/plugin/ \
    && cp /usr/lib/mysql/plugin/* /usr/lib/mysql/plugin/ || true
