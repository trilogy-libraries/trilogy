ARG DISTRIBUTION=debian:bookworm
FROM ${DISTRIBUTION}
LABEL maintainer="github@github.com"

RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y build-essential ca-certificates wget libssl-dev default-libmysqlclient-dev clang clang-tools llvm valgrind netcat-traditional

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

RUN wget https://github.com/postmodern/ruby-install/releases/download/v0.10.1/ruby-install-0.10.1.tar.gz && \
    tar -xzvf ruby-install-0.10.1.tar.gz && \
    cd ruby-install-0.10.1/ && \
    make install

ARG RUBY_VERSION=3.4
RUN ruby-install --system ruby ${RUBY_VERSION} -- --disable-install-doc
RUN ruby --version

WORKDIR /app
COPY . .

CMD ["script/test"]
