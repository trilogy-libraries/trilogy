FROM ruby:latest

LABEL maintainer="github@github.com"  
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update -qq && apt-get install --no-install-recommends -y \
    build-essential libssl-dev default-libmysqlclient-dev clang valgrind netcat \
    ruby ruby-dev ruby-bundler mysql-server

# Set up the MySQL server with user and empty database
RUN service mysql start && mysql -e "CREATE USER 'codespaces'@'localhost';" && \
    mysql -e "CREATE DATABASE dev;" && \
    mysql -e "GRANT ALL PRIVILEGES ON dev.* TO 'codespaces'@'localhost';" && \
    mysql -e "FLUSH PRIVILEGES;"

WORKDIR /app  
COPY . .  

# CMD service mysql start

