# frozen_string_literal: true

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

  # Trilogy may raise various syscall errors, which we treat as Trilogy::Errors.
  class SyscallError
    ERRORS = {}

    Errno.constants
      .map { |c| Errno.const_get(c) }.uniq
      .select { |c| c.is_a?(Class) && c < SystemCallError }
      .each do |c|
        errno_name = c.to_s.split('::').last
        ERRORS[c::Errno] = const_set(errno_name, Class.new(c) { include Trilogy::Error })
      end

    ERRORS.freeze

    class << self
      def from_errno(errno, message)
        ERRORS[errno].new(message)
      end
    end
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
  end

  class ConnectionResetError < Errno::ECONNRESET
    include ConnectionError
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

  MYSQL_TO_RUBY_ENCODINGS_MAP = {
    "big5"     => "Big5",
    "dec8"     => nil,
    "cp850"    => "CP850",
    "hp8"      => nil,
    "koi8r"    => "KOI8-R",
    "latin1"   => "ISO-8859-1",
    "latin2"   => "ISO-8859-2",
    "swe7"     => nil,
    "ascii"    => "US-ASCII",
    "ujis"     => "eucJP-ms",
    "sjis"     => "Shift_JIS",
    "hebrew"   => "ISO-8859-8",
    "tis620"   => "TIS-620",
    "euckr"    => "EUC-KR",
    "koi8u"    => "KOI8-R",
    "gb2312"   => "GB2312",
    "greek"    => "ISO-8859-7",
    "cp1250"   => "Windows-1250",
    "gbk"      => "GBK",
    "latin5"   => "ISO-8859-9",
    "armscii8" => nil,
    "utf8"     => "UTF-8",
    "ucs2"     => "UTF-16BE",
    "cp866"    => "IBM866",
    "keybcs2"  => nil,
    "macce"    => "macCentEuro",
    "macroman" => "macRoman",
    "cp852"    => "CP852",
    "latin7"   => "ISO-8859-13",
    "utf8mb4"  => "UTF-8",
    "cp1251"   => "Windows-1251",
    "utf16"    => "UTF-16",
    "cp1256"   => "Windows-1256",
    "cp1257"   => "Windows-1257",
    "utf32"    => "UTF-32",
    "binary"   => "ASCII-8BIT",
    "geostd8"  => nil,
    "cp932"    => "Windows-31J",
    "eucjpms"  => "eucJP-ms",
    "utf16le"  => "UTF-16LE",
    "gb18030"  => "GB18030",
  }.freeze

  def initialize(options = {})
    mysql_encoding = options[:encoding] || "utf8mb4"
    unless rb_encoding = MYSQL_TO_RUBY_ENCODINGS_MAP[mysql_encoding]
      raise ArgumentError, "Unknown or unsupported encoding: #{mysql_encoding}"
    end
    encoding = Encoding.find(rb_encoding)
    charset = charset_for_mysql_encoding(mysql_encoding)
    _initialize(encoding, charset, **options)
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

  def max_allowed_packet
    @max_allowed_packet ||= query_with_flags("select @@max_allowed_packet", query_flags | QUERY_FLAGS_FLATTEN_ROWS).rows.first
  end

  def query_with_flags(sql, flags)
    old_flags = query_flags
    self.query_flags = flags

    query(sql)
  ensure
    self.query_flags = old_flags
  end

  class Result
    attr_reader :fields, :rows, :query_time, :affected_rows, :last_insert_id

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

  private

  def charset_for_mysql_encoding(mysql_encoding)
    @mysql_encodings_map ||= {
      "big5"     => CHARSET_BIG5_CHINESE_CI,
      "cp850"    => CHARSET_CP850_GENERAL_CI,
      "koi8r"    => CHARSET_KOI8R_GENERAL_CI,
      "latin1"   => CHARSET_LATIN1_GENERAL_CI,
      "latin2"   => CHARSET_LATIN2_GENERAL_CI,
      "ascii"    => CHARSET_ASCII_GENERAL_CI,
      "ujis"     => CHARSET_UJIS_JAPANESE_CI,
      "sjis"     => CHARSET_SJIS_JAPANESE_CI,
      "hebrew"   => CHARSET_HEBREW_GENERAL_CI,
      "tis620"   => CHARSET_TIS620_THAI_CI,
      "euckr"    => CHARSET_EUCKR_KOREAN_CI,
      "koi8u"    => CHARSET_KOI8U_GENERAL_CI,
      "gb2312"   => CHARSET_GB2312_CHINESE_CI,
      "greek"    => CHARSET_GREEK_GENERAL_CI,
      "cp1250"   => CHARSET_CP1250_GENERAL_CI,
      "gbk"      => CHARSET_GBK_CHINESE_CI,
      "latin5"   => CHARSET_LATIN5_TURKISH_CI,
      "utf8"     => CHARSET_UTF8_GENERAL_CI,
      "ucs2"     => CHARSET_UCS2_GENERAL_CI,
      "cp866"    => CHARSET_CP866_GENERAL_CI,
      "cp932"    => CHARSET_CP932_JAPANESE_CI,
      "eucjpms"  => CHARSET_EUCJPMS_JAPANESE_CI,
      "utf16le"  => CHARSET_UTF16_GENERAL_CI,
      "gb18030"  => CHARSET_GB18030_CHINESE_CI,
      "macce"    => CHARSET_MACCE_GENERAL_CI,
      "macroman" => CHARSET_MACROMAN_GENERAL_CI,
      "cp852"    => CHARSET_CP852_GENERAL_CI,
      "latin7"   => CHARSET_LATIN7_GENERAL_CI,
      "utf8mb4"  => CHARSET_UTF8MB4_GENERAL_CI,
      "cp1251"   => CHARSET_CP1251_GENERAL_CI,
      "utf16"    => CHARSET_UTF16_GENERAL_CI,
      "cp1256"   => CHARSET_CP1256_GENERAL_CI,
      "cp1257"   => CHARSET_CP1257_GENERAL_CI,
      "utf32"    => CHARSET_UTF32_GENERAL_CI,
      "binary"   => CHARSET_BINARY,
    }.freeze
    @mysql_encodings_map[mysql_encoding]
  end
end

require "trilogy/cext"
