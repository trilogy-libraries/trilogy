ARG DISTRIBUTION=ubuntu:jammy
FROM ${DISTRIBUTION}
LABEL maintainer="github@github.com"

RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y build-essential ca-certificates wget libssl-dev default-libmysqlclient-dev clang clang-tools llvm valgrind netcat

RUN update-ca-certificates

RUN wget https://github.com/postmodern/ruby-install/releases/download/v0.9.0/ruby-install-0.9.0.tar.gz && \
    tar -xzvf ruby-install-0.9.0.tar.gz && \
    cd ruby-install-0.9.0/ && \
    make install

ARG RUBY_VERSION=3.2
RUN ruby-install --system ruby ${RUBY_VERSION}
RUN ruby --version

WORKDIR /app
COPY . .

CMD ["script/test"]
