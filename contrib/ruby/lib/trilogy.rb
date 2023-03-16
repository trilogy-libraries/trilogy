require "trilogy/version"

class Trilogy
  # Trilogy::Error is the base error type. All errors raised by Trilogy
  # should be descendants of Trilogy::Error
  module Error
    attr_reader :error_code
  end

  # Trilogy::ConnectionError is the base error type for all potentially transient
  # network errors.
  module ConnectionError
    include Error
  end

  class BaseError < StandardError
    include Error

    def initialize(error_message = nil, error_code = nil)
      message = error_code ? "#{error_code}: #{error_message}" : error_message
      super(message)
      @error_code = error_code
    end
  end

  class BaseConnectionError < BaseError
    include ConnectionError
  end

  # Trilogy::ClientError is the base error type for invalid queries or parameters
  # that shouldn't be retried.
  class ClientError < BaseError
    include Error
  end

  class QueryError < ClientError
  end

  class CastError < ClientError
  end

  class TimeoutError < Errno::ETIMEDOUT
    include ConnectionError

    def initialize(error_message = nil, error_code = nil)
      super
      @error_code = error_code
    end
  end

  class ConnectionRefusedError < Errno::ECONNREFUSED
    include ConnectionError

    def initialize(error_message = nil, error_code = nil)
      super
      @error_code = error_code
    end
  end

  class ConnectionResetError < Errno::ECONNRESET
    include ConnectionError

    def initialize(error_message = nil, error_code = nil)
      super
      @error_code = error_code
    end
  end

  # DatabaseError was replaced by ProtocolError, but we'll keep it around as an
  # ancestor of ProtocolError for compatibility reasons (e.g. so `rescue DatabaseError`
  # still works. We can remove this class in the next major release.
  module DatabaseError
  end

  class ProtocolError < BaseError
    include DatabaseError

    ERROR_CODES = {
      1205 => TimeoutError, # ER_LOCK_WAIT_TIMEOUT
      1044 => BaseConnectionError, # ER_DBACCESS_DENIED_ERROR
      1045 => BaseConnectionError, # ER_ACCESS_DENIED_ERROR
      1064 => QueryError, # ER_PARSE_ERROR
      1152 => BaseConnectionError, # ER_ABORTING_CONNECTION
      1153 => BaseConnectionError, # ER_NET_PACKET_TOO_LARGE
      1154 => BaseConnectionError, # ER_NET_READ_ERROR_FROM_PIPE
      1155 => BaseConnectionError, # ER_NET_FCNTL_ERROR
      1156 => BaseConnectionError, # ER_NET_PACKETS_OUT_OF_ORDER
      1157 => BaseConnectionError, # ER_NET_UNCOMPRESS_ERROR
      1158 => BaseConnectionError, # ER_NET_READ_ERROR
      1159 => BaseConnectionError, # ER_NET_READ_INTERRUPTED
      1160 => BaseConnectionError, # ER_NET_ERROR_ON_WRITE
      1161 => BaseConnectionError, # ER_NET_WRITE_INTERRUPTED
      1927 => BaseConnectionError, # ER_CONNECTION_KILLED
    }
    class << self
      def from_code(message, code)
        ERROR_CODES.fetch(code, self).new(message, code)
      end
    end
  end

  class SSLError < BaseError
    include ConnectionError
  end

  class ConnectionClosed < IOError
    include ConnectionError
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

  class Result
    attr_reader :fields, :rows, :query_time

    def count
      rows.count
    end

    def each_hash
      return enum_for(:each_hash) unless block_given?

      rows.each do |row|
        this_row = {}

        idx = 0
        row.each do |col|
          this_row[fields[idx]] = col
          idx += 1
        end

        yield this_row
      end

      self
    end

    def each(&bk)
      rows.each(&bk)
    end

    include Enumerable
  end
end

require "trilogy/cext"
