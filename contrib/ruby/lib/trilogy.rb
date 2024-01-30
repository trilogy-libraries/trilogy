# frozen_string_literal: true

require "trilogy/version"
require "trilogy/error"
require "trilogy/result"
require "trilogy/cext"
require "trilogy/encoding"

class Trilogy
  VALID_OPTIONS = %i[
    host port path database username password encoding
    ssl ssl_mode ssl_cipher ssl_ca ssl_capath ssl_key ssl_cert
    tls_min_version tls_max_version tls_ciphersuites
    read_timeout write_timeout connect_timeout
    multi_statement
  ].freeze

  def initialize(options = {})
    invalid_keys = options.keys - VALID_OPTIONS
    $stderr.puts "WARNING: Unknown Trilogy options: #{invalid_keys.join(", ")}" unless invalid_keys.empty?

    options[:port] = options[:port].to_i if options[:port]
    mysql_encoding = options[:encoding] || "utf8mb4"
    encoding = Trilogy::Encoding.find(mysql_encoding)
    charset = Trilogy::Encoding.charset(mysql_encoding)
    @connection_options = options
    @connected_host = nil

    _connect(encoding, charset, options)
  end

  def connection_options
    @connection_options.dup.freeze
  end

  def in_transaction?
    (server_status & SERVER_STATUS_IN_TRANS) != 0
  end

  def server_info
    version_str = server_version

    if /\A(\d+)\.(\d+)\.(\d+)/ =~ version_str
      version_num = ($1.to_i * 10000) + ($2.to_i * 100) + $3.to_i
    end

    { :version => version_str, :id => version_num }
  end

  def connected_host
    @connected_host ||= query_with_flags("select @@hostname", query_flags | QUERY_FLAGS_FLATTEN_ROWS).rows.first
  end

  def query_with_flags(sql, flags)
    old_flags = query_flags
    self.query_flags = flags

    query(sql)
  ensure
    self.query_flags = old_flags
  end
end
