ARG DISTRIBUTION=ubuntu:jammy

FROM ${DISTRIBUTION}
LABEL maintainer="github@github.com"
ARG RUBY_VERSION=3.2
# Make all apt-get commands non-interactive. Setting this as an ARG will apply to the entire
# build phase, but not leak into the final image and run phase.
ARG DEBIAN_FRONTEND=noninteractive

# Install system dependencies.
RUN apt-get update --quiet=2 \
    && apt-get install --quiet --yes \
      apt-transport-https \
      ca-certificates \
      curl \
      gnupg

# Install Ruby dependencies.
RUN apt-get update --quiet=2 \
    && apt-get install --yes --no-install-recommends \
      autoconf \
      bison \
      patch \
      build-essential \
      rustc \
      libssl-dev \
      libyaml-dev \
      libreadline-dev \
      zlib1g-dev \
      libgmp-dev \
      libncurses-dev \
      libffi-dev \
      libgdbm-dev \
      libdb-dev \
      uuid-dev \
      # Other dependencies...
      default-libmysqlclient-dev \
      clang \
      clang-tools \
      llvm \
      valgrind \
      netcat

RUN update-ca-certificates

RUN if which ruby >/dev/null 2>&1; then \
      echo "Ruby is already installed: $(ruby --version)"; \
    else \
      curl --location \
        "https://github.com/rbenv/ruby-build/archive/refs/tags/$(basename $(curl --location --silent --output /dev/null --write-out %{url_effective} https://github.com/rbenv/ruby-build/releases/latest)).tar.gz" \
          | tar --extract --gzip \
      && PREFIX=/usr/local ./ruby-build-*/install.sh \
      && rm -rf ./ruby-build-*/install.sh \
      && ruby-build ${RUBY_VERSION} /usr/local \
      && echo "Installed Ruby: $(ruby --version)"; \
    fi

WORKDIR /app
COPY . .

CMD ["script/test"]
