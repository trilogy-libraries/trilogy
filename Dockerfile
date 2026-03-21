ARG DISTRIBUTION=debian:bookworm
FROM ${DISTRIBUTION}
LABEL maintainer="github@github.com"

RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y \
    build-essential \
    git-core \
    autoconf \
    ca-certificates \
    curl \
    libssl-dev \
    default-libmysqlclient-dev \
    clang clang-tools \
    llvm \
    valgrind \
    libffi-dev \
    libyaml-dev \
    ruby \
    netcat-traditional

# Install libclang-rt-14-dev for Debian Bookworm so that Trilogy builds.
ARG DISTRIBUTION=debian:bookworm
RUN if [ "${DISTRIBUTION}" = "debian:bookworm" ]; then \
    DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y libclang-rt-14-dev; \
    fi

# Install libclang-rt-18-dev for Ubuntu Noble so that Trilogy builds.
RUN if [ "${DISTRIBUTION}" = "ubuntu:noble" ]; then \
    DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y libclang-rt-18-dev; \
    fi

RUN update-ca-certificates

RUN git clone --depth 1 --single-branch https://github.com/rbenv/ruby-build.git /opt/ruby-build/

ARG RUBY_VERSION=3.4.9
ARG RUBY_BUILD_OPTS=""

RUN CONFIGURE_OPTS="--disable-install-doc ${RUBY_BUILD_OPTS}" /opt/ruby-build/bin/ruby-build ${RUBY_VERSION} /opt/ruby-${RUBY_VERSION}

ENV PATH=/opt/ruby-${RUBY_VERSION}/bin:$PATH

RUN ruby --version

WORKDIR /app
COPY . .

CMD ["script/test"]
