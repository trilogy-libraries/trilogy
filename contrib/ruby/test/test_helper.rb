require "trilogy"
require "socket"
require "timeout"

require "minitest/autorun"

$LOAD_PATH.unshift File.expand_path("../../lib", __FILE__)
$LOAD_PATH.unshift File.expand_path("../", __FILE__)

class TrilogyTest < Minitest::Test
  DEFAULT_HOST = ENV["MYSQL_HOST"] || "127.0.0.1"
  DEFAULT_PORT = (port = ENV["MYSQL_PORT"].to_i) && port != 0 ? port : 3306
  DEFAULT_USER = ENV["MYSQL_USER"] || "root"
  DEFAULT_PASS = ENV["MYSQL_PASS"]

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
end
