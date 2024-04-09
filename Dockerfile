ARG DISTRIBUTION=ubuntu:jammy

FROM ${DISTRIBUTION}
LABEL maintainer="github@github.com"
ARG RUBY_VERSION=3.2
# Make all apt-get commands non-interactive. Setting this as an ARG will apply to the entire
# build phase, but not leak into the final image and run phase.
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update -qq \
    && apt-get install --yes --no-install-recommends \
      build-essential \
      ca-certificates \
      wget \
      libssl-dev \
      default-libmysqlclient-dev \
      clang clang-tools \
      llvm \
      valgrind \
      netcat

RUN update-ca-certificates

RUN wget https://github.com/postmodern/ruby-install/releases/download/v0.9.0/ruby-install-0.9.0.tar.gz \
    && tar -xzvf ruby-install-0.9.0.tar.gz \
    && cd ruby-install-0.9.0 \
    && make install

RUN ruby-install --system ruby ${RUBY_VERSION}
RUN ruby --version

WORKDIR /app
COPY . .

CMD ["script/test"]
