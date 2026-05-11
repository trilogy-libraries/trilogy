# frozen_string_literal: true

require "trilogy"

count = Integer(ENV["COUNT"] || 50)

default_ssl = ENV.fetch("TRILOGY_DEFAULT_SSL", "true") != "false"
default_ssl_mode = default_ssl ? Trilogy::SSL_PREFERRED_NOVERIFY : Trilogy::SSL_DISABLED

conn = Trilogy.new(
  host: ENV["MYSQL_HOST"] || "127.0.0.1",
  port: (port = ENV["MYSQL_PORT"].to_i) && port != 0 ? port : 3306,
  username: ENV["MYSQL_USER"] || "root",
  password: ENV["MYSQL_PASS"],
  ssl: default_ssl,
  ssl_mode: default_ssl_mode,
  tls_min_version: Trilogy::TLS_VERSION_12,
  
)
conn.ping
pipe = IO.pipe.last

if pipe.fileno > 20
  raise "latest FD reached #{pipe.fileno}, FD leak on exec is likely"
end

if count > 0
  ENV["COUNT"] = (count - 1).to_s
  Process.exec("ruby", $0)
end
