ARG DISTRIBUTION=debian:buster
FROM ${DISTRIBUTION}
LABEL maintainer="github@github.com"

RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y build-essential libssl-dev default-libmysqlclient-dev clang clang-tools valgrind netcat ruby ruby-dev ruby-bundler

WORKDIR /app
COPY . .

CMD ["script/test"]
