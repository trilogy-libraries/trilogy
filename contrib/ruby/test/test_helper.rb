require "trilogy"
require "socket"
require "timeout"

require "minitest/autorun"

$LOAD_PATH.unshift File.expand_path("../../lib", __FILE__)
$LOAD_PATH.unshift File.expand_path("../", __FILE__)

if GC.respond_to?(:verify_compaction_references)
  # This method was added in Ruby 3.0.0. Calling it this way asks the GC to
  # move objects around, helping to find object movement bugs.
  if Gem::Version::new(RUBY_VERSION) >= Gem::Version::new("3.2.0")
    # double_heap is deprecated and expand_heap is the updated argument. This change
    # was introduced in:
    # https://github.com/ruby/ruby/commit/a6dd859affc42b667279e513bb94fb75cfb133c1
    GC.verify_compaction_references(expand_heap: true, toward: :empty)
  else
    GC.verify_compaction_references(double_heap: true, toward: :empty)
  end
end

class TrilogyTest < Minitest::Test
  DEFAULT_HOST = (ENV["MYSQL_HOST"] || "127.0.0.1").freeze
  DEFAULT_PORT = (port = ENV["MYSQL_PORT"].to_i) && port != 0 ? port : 3306
  DEFAULT_USER = (ENV["MYSQL_USER"] || "root").freeze
  DEFAULT_PASS = ENV["MYSQL_PASS"].freeze

  def assert_equal_timestamp(time1, time2)
    assert_equal time1.to_i, time2.to_i
    assert_equal time1.utc_offset, time2.utc_offset
  end

  def allocations
    before = GC.stat :total_allocated_objects
    yield
    after = GC.stat :total_allocated_objects
    after - before
  end

  def new_tcp_client(opts = {})
    defaults = {
      host: DEFAULT_HOST,
      port: DEFAULT_PORT,
      username: DEFAULT_USER,
      password: DEFAULT_PASS,
      ssl: true,
      ssl_mode: Trilogy::SSL_PREFERRED_NOVERIFY,
      tls_min_version: Trilogy::TLS_VERSION_12,
    }.merge(opts)

    c = Trilogy.new defaults
    c.query "SET SESSION sql_mode = ''"
    c
  end

  def new_unix_client(socket, opts = {})
    defaults = {
      username: DEFAULT_USER,
      password: DEFAULT_PASS,
      socket: socket,
    }.merge(opts)

    c = Trilogy.new defaults
    c.query "SET SESSION sql_mode = ''"
    c
  end

  @@server_global_variables = Hash.new do |h, k|
    client = Trilogy.new(
      host: DEFAULT_HOST,
      port: DEFAULT_PORT,
      username: DEFAULT_USER,
      password: DEFAULT_PASS,
    )
    name = k
    result = client.query("SHOW GLOBAL VARIABLES LIKE '#{client.escape name}'")
    if result.count == 0
      h[k] = nil
    else
      h[k] = result.rows[0][1]
    end
  end

  def server_global_variable(name)
    @@server_global_variables[name]
  end

  def ensure_closed(socket)
    socket.close if socket
  end

  def create_and_delete_test_user(opts = {}, &block)
    client = new_tcp_client
    user_created = create_test_user(client, opts)
    yield
  ensure
    delete_test_user(client, opts) if user_created
    ensure_closed client
  end

  def create_test_user(client, opts = {})
    username = opts[:username]
    password = opts[:password] || "password"
    host = opts[:host] || DEFAULT_HOST
    auth_plugin = opts[:auth_plugin]

    raise ArgumentError if username.nil? || auth_plugin.nil?
    user_exists = client.query("SELECT user FROM mysql.user WHERE user = '#{username}';").rows.first
    return if user_exists

    client.query("CREATE USER '#{username}'@'#{host}'")
    client.query("GRANT ALL PRIVILEGES ON test.* TO '#{username}'@'#{host}';")
    client.query("ALTER USER '#{username}'@'#{host}' IDENTIFIED WITH #{auth_plugin} BY '#{password}';")
    client.query("SELECT user FROM mysql.user WHERE user = '#{username}';").rows.first
  end

  def delete_test_user(client, opts = {})
    username = opts[:username] || "auth_user"
    host = opts[:host] || DEFAULT_HOST

    client.query("DROP USER IF EXISTS '#{username}'@'#{host}'")
  end

  def create_test_table(client)
    client.change_db "test"

    client.query("DROP TABLE IF EXISTS trilogy_test")

    sql = <<-SQL
    CREATE TABLE `trilogy_test` (
      `id` INT(11) NOT NULL AUTO_INCREMENT,
      `null_test` VARCHAR(10) DEFAULT NULL,
      `bit_test` BIT(64) DEFAULT NULL,
      `single_bit_test` BIT(1) DEFAULT NULL,
      `tiny_int_test` TINYINT(4) DEFAULT NULL,
      `bool_cast_test` TINYINT(1) DEFAULT NULL,
      `small_int_test` SMALLINT(6) DEFAULT NULL,
      `medium_int_test` MEDIUMINT(9) DEFAULT NULL,
      `int_test` INT(11) DEFAULT NULL,
      `big_int_test` BIGINT(20) DEFAULT NULL,
      `unsigned_big_int_test` BIGINT(20) UNSIGNED DEFAULT NULL,
      `float_test` FLOAT(10,3) DEFAULT NULL,
      `float_zero_test` FLOAT(10,3) DEFAULT NULL,
      `double_test` DOUBLE(10,3) DEFAULT NULL,
      `decimal_test` DECIMAL(10,3) DEFAULT NULL,
      `decimal_zero_test` DECIMAL(10,3) DEFAULT NULL,
      `date_test` DATE DEFAULT NULL,
      `date_time_test` DATETIME DEFAULT NULL,
      `date_time_with_precision_test` DATETIME(3) DEFAULT NULL,
      `time_with_precision_test` TIME(3) DEFAULT NULL,
      `timestamp_test` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      `time_test` TIME DEFAULT NULL,
      `year_test` YEAR(4) DEFAULT NULL,
      `char_test` CHAR(10) DEFAULT NULL,
      `varchar_test` VARCHAR(10) DEFAULT NULL,
      `binary_test` BINARY(10) DEFAULT NULL,
      `varbinary_test` VARBINARY(10) DEFAULT NULL,
      `tiny_blob_test` TINYBLOB,
      `tiny_text_test` TINYTEXT,
      `blob_test` BLOB,
      `text_test` TEXT,
      `medium_blob_test` MEDIUMBLOB,
      `medium_text_test` MEDIUMTEXT,
      `long_blob_test` LONGBLOB,
      `long_text_test` LONGTEXT,
      `enum_test` ENUM('val1','val2') DEFAULT NULL,
      `set_test` SET('val1','val2') DEFAULT NULL,
      PRIMARY KEY (`id`)
    ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
    SQL

    client.query sql
  end

  def assert_raises_connection_error(&block)
    err = assert_raises(Trilogy::Error, &block)

    if err.is_a?(Trilogy::EOFError)
      assert_includes err.message, "TRILOGY_CLOSED_CONNECTION"
    elsif err.is_a?(Trilogy::SSLError)
      assert_includes err.message, "unexpected eof while reading"
    else
      assert_instance_of Trilogy::ConnectionResetError, err
    end

    err
  end

  def build_mysql_handshake_packet
    protocol_version = 10
    server_version = "8.0.24\0"  # null-terminated string
    connection_id = [1234].pack("V")
    auth_plugin_data_part1 = "12345678"
    filler = "\0"
    capability_flags_lower = [0xFFFF].pack("v")  # All capabilities enabled for testing
    character_set = "\x21"  # utf8_general_ci
    status_flags = [0x0002].pack("v")  # SERVER_STATUS_AUTOCOMMIT
    capability_flags_upper = [0xFFFF].pack("v")  # All capabilities enabled for testing
    auth_plugin_data_length = "\x15"  # 21 bytes of auth data total
    reserved = "\0" * 10
    auth_plugin_data_part2 = "123456789012345"
    auth_plugin_name = "mysql_native_password\0"

    handshake = [
      protocol_version,
      server_version,
      connection_id,
      auth_plugin_data_part1,
      filler,
      capability_flags_lower,
      character_set,
      status_flags,
      capability_flags_upper,
      auth_plugin_data_length,
      reserved,
      auth_plugin_data_part2,
      auth_plugin_name
    ].pack("CA*A*A8A*A*A*A*A*A*A*A*A*")

    # Add MySQL packet header (4 bytes: 3 bytes length + 1 byte sequence id)
    packet_length = [handshake.length].pack("V")[0..2]  # Only first 3 bytes
    sequence_id = "\0"

    packet_length + sequence_id + handshake
  end

  def upgrade_socket_to_ssl(socket)
    ssl_ctx = OpenSSL::SSL::SSLContext.new
    ssl_ctx.ciphers = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:AES128-GCM-SHA256"
    ssl_ctx.min_version = OpenSSL::SSL::TLS1_2_VERSION
    ssl_ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
    
    # Generate a self-signed certificate
    key = OpenSSL::PKey::RSA.new(2048)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = OpenSSL::X509::Name.parse("/CN=localhost")
    cert.issuer = cert.subject
    cert.public_key = key.public_key
    cert.not_before = Time.now
    cert.not_after = Time.now + 3600  # Valid for 1 hour
    
    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = cert
    ef.issuer_certificate = cert
    cert.add_extension(ef.create_extension("basicConstraints", "CA:TRUE", true))
    cert.add_extension(ef.create_extension("keyUsage", "keyCertSign, cRLSign", true))
    cert.add_extension(ef.create_extension("subjectKeyIdentifier", "hash"))
    cert.sign(key, OpenSSL::Digest.new('SHA256'))
    
    ssl_ctx.key = key
    ssl_ctx.cert = cert
    
    OpenSSL::SSL::SSLSocket.new(socket, ssl_ctx)
  end

end
