require "test_helper"

class CastTest < TrilogyTest
  def setup
    @client = new_tcp_client
    create_test_table(@client)
    super
  end

  def teardown
    ensure_closed @client
    super
  end

  def test_disable_casting
    @client.query_flags = Trilogy::QUERY_FLAGS_NONE

    assert_equal [["1"]], @client.query("SELECT 1").to_a
  end

  def test_bit_cast
    @client.query(<<-SQL)
      INSERT INTO trilogy_test (bit_test, single_bit_test) VALUES (0, 0), (1, 1)
    SQL

    results = @client.query(<<-SQL).to_a
      SELECT bit_test, single_bit_test FROM trilogy_test ORDER BY id ASC
    SQL

    assert_equal [
      ["\x00\x00\x00\x00\x00\x00\x00\x00".b, "\x00"],
      ["\x00\x00\x00\x00\x00\x00\x00\x01".b, "\x01"],
    ], results

    @client.query_flags |= Trilogy::QUERY_FLAGS_CAST_BOOLEANS

    results = @client.query(<<-SQL).to_a
      SELECT single_bit_test FROM trilogy_test ORDER BY id ASC
    SQL

    assert_equal [[false], [true]], results
  end

  def test_tiny_int_cast
    @client.query(<<-SQL)
      INSERT INTO trilogy_test (tiny_int_test, bool_cast_test) VALUES (0, 0), (1, 1)
    SQL

    results = @client.query(<<-SQL).to_a
      SELECT tiny_int_test, bool_cast_test FROM trilogy_test ORDER BY id ASC
    SQL

    assert_equal [
      [0, 0],
      [1, 1],
    ], results

    @client.query_flags |= Trilogy::QUERY_FLAGS_CAST_BOOLEANS

    results = @client.query(<<-SQL).to_a
      SELECT bool_cast_test FROM trilogy_test ORDER BY id ASC
    SQL

    assert_equal [[false], [true]], results
  end

  def test_integer_cast
    @client.query(<<-SQL)
      INSERT INTO trilogy_test (small_int_test, medium_int_test, int_test, big_int_test, year_test)
      VALUES (123, 456, 789, 999999999999999999, 1994)
    SQL

    results = @client.query(<<-SQL).to_a
      SELECT small_int_test, medium_int_test, int_test, big_int_test, year_test FROM trilogy_test
    SQL

    assert_equal [[123, 456, 789, 999999999999999999, 1994]], results
  end

  def test_negative_integer_cast
    @client.query(<<-SQL)
      INSERT INTO trilogy_test (small_int_test, medium_int_test, int_test, big_int_test)
      VALUES (-123, -456, -789, -999999999999999999)
    SQL

    results = @client.query(<<-SQL).to_a
      SELECT small_int_test, medium_int_test, int_test, big_int_test FROM trilogy_test
    SQL

    assert_equal [[-123, -456, -789, -999999999999999999]], results
  end

  def test_integer_range_max
    @client.query(<<-SQL)
      INSERT INTO trilogy_test (tiny_int_test, small_int_test, medium_int_test, int_test, big_int_test, unsigned_big_int_test)
      VALUES (127, 32767, 8388607,  2147483647, 9223372036854775807, 18446744073709551615)
    SQL

    results = @client.query(<<-SQL).to_a
      SELECT tiny_int_test, small_int_test, medium_int_test, int_test, big_int_test, unsigned_big_int_test FROM trilogy_test
    SQL

    assert_equal [[127, 32767, 8388607,  2147483647, 9223372036854775807, 18446744073709551615]], results
  end

  def test_integer_range_min
    @client.query(<<-SQL)
      INSERT INTO trilogy_test (tiny_int_test, small_int_test, medium_int_test, int_test, big_int_test, unsigned_big_int_test)
      VALUES (-128, -32768, -8388608, -2147483648, -9223372036854775808, 0)
    SQL

    results = @client.query(<<-SQL).to_a
      SELECT tiny_int_test, small_int_test, medium_int_test, int_test, big_int_test, unsigned_big_int_test FROM trilogy_test
    SQL

    assert_equal [[-128, -32768, -8388608, -2147483648, -9223372036854775808, 0]], results
  end

  def test_float_cast
    @client.query(<<-SQL)
      INSERT INTO trilogy_test (float_test, double_test)
      VALUES (12.34, 56.78)
    SQL

    results = @client.query(<<-SQL).to_a
      SELECT float_test, double_test FROM trilogy_test
    SQL

    assert_equal [[12.34, 56.78]], results
  end

  def test_decimal_cast
    @client.query(<<-SQL)
      INSERT INTO trilogy_test (decimal_test)
      VALUES (12.34)
    SQL

    results = @client.query(<<-SQL).to_a
      SELECT decimal_test FROM trilogy_test
    SQL

    assert_equal [[12.34]], results

    assert_kind_of BigDecimal, results[0][0]
  end

  def test_date_cast
    @client.query(<<-SQL)
      INSERT INTO trilogy_test (date_test)
      VALUES ("1980-08-27")
    SQL

    results = @client.query(<<-SQL).to_a
      SELECT date_test FROM trilogy_test
    SQL

    assert_equal [[Date.new(1980, 8, 27)]], results

    assert_kind_of Date, results[0][0]
  end

  def test_time_cast_defaults_to_utc
    time = Time.utc(2000, 1, 1, 0, 26, 0)

    @client.query(<<-SQL)
      INSERT INTO trilogy_test (time_test)
      VALUES ("#{time.strftime("%H:%M:%S")}")
    SQL

    results = @client.query(<<-SQL).to_a
      SELECT time_test FROM trilogy_test
    SQL

    assert_equal [[time]], results

    assert_kind_of Time, results[0][0]
  end

  def test_time_cast_utc
    time = Time.utc(2000, 1, 1, 0, 26, 0)

    # default cast option is UTC

    @client.query(<<-SQL)
      INSERT INTO trilogy_test (time_test)
      VALUES ("#{time.strftime("%H:%M:%S")}")
    SQL

    results = @client.query(<<-SQL).to_a
      SELECT time_test FROM trilogy_test
    SQL

    assert_equal [[time]], results

    assert_kind_of Time, results[0][0]
  end

  def test_time_cast_local
    time = Time.local(2000, 1, 1, 0, 26, 0)

    @client.query_flags |= Trilogy::QUERY_FLAGS_LOCAL_TIMEZONE

    @client.query(<<-SQL)
      INSERT INTO trilogy_test (time_test)
      VALUES ("#{time.strftime("%H:%M:%S")}")
    SQL

    results = @client.query(<<-SQL).to_a
      SELECT time_test FROM trilogy_test
    SQL

    assert_equal [[time]], results

    assert_kind_of Time, results[0][0]
  end

  def test_timestamp_cast_defaults_to_utc
    @client.query(<<-SQL)
      INSERT INTO trilogy_test (null_test)
      VALUES (NULL)
    SQL

    results = @client.query(<<-SQL).to_a
      SELECT timestamp_test FROM trilogy_test
    SQL

    assert_kind_of Time, results[0][0]
    assert results[0][0].utc?
  end

  def test_timestamp_cast_utc
    @client.query(<<-SQL)
      INSERT INTO trilogy_test (null_test)
      VALUES (NULL)
    SQL

    results = @client.query(<<-SQL).to_a
      SELECT timestamp_test FROM trilogy_test
    SQL

    assert_kind_of Time, results[0][0]
    assert results[0][0].utc?
  end

  def test_timestamp_cast_local
    @client.query_flags |= Trilogy::QUERY_FLAGS_LOCAL_TIMEZONE

    @client.query(<<-SQL)
      INSERT INTO trilogy_test (null_test)
      VALUES (NULL)
    SQL

    results = @client.query(<<-SQL).to_a
      SELECT timestamp_test FROM trilogy_test
    SQL

    assert_kind_of Time, results[0][0]
    assert !results[0][0].utc?
  end

  def test_datetime_cast_defaults_to_utc
    time = Time.now.utc

    @client.query(<<-SQL)
      INSERT INTO trilogy_test (date_time_test)
      VALUES ("#{time.strftime("%Y-%m-%d %H:%M:%S")}")
    SQL

    results = @client.query(<<-SQL).to_a
      SELECT date_time_test FROM trilogy_test
    SQL

    assert_equal_timestamp time, results[0][0]

    assert_kind_of Time, results[0][0]
  end

  def test_datetime_cast_utc
    time = Time.now.utc

    @client.query(<<-SQL)
      INSERT INTO trilogy_test (date_time_test)
      VALUES ("#{time.strftime("%Y-%m-%d %H:%M:%S")}")
    SQL

    results = @client.query(<<-SQL).to_a
      SELECT date_time_test FROM trilogy_test
    SQL

    assert_equal_timestamp time, results[0][0]

    assert_kind_of Time, results[0][0]
  end

  def test_datetime_cast_local
    time = Time.now.localtime

    @client.query_flags |= Trilogy::QUERY_FLAGS_LOCAL_TIMEZONE

    @client.query(<<-SQL)
      INSERT INTO trilogy_test (date_time_test)
      VALUES ("#{time.strftime("%Y-%m-%d %H:%M:%S")}")
    SQL

    results = @client.query(<<-SQL).to_a
      SELECT date_time_test FROM trilogy_test
    SQL

    assert_equal_timestamp time, results[0][0]

    assert_kind_of Time, results[0][0]
  end

  def test_datetime_cast_with_precision
    @client.query(<<-SQL)
      INSERT INTO trilogy_test (date_time_with_precision_test)
      VALUES ("2018-06-08 08:38:18.108")
    SQL

    results = @client.query(<<-SQL).to_a
      SELECT date_time_with_precision_test FROM trilogy_test
    SQL

    time = results[0][0]

    assert_kind_of Time, time
    assert_equal "2018-06-08 08:38:18 UTC", time.to_s
    assert_equal 108000, time.usec
  end

  def test_binary_cast
    @client.query(<<-SQL)
      INSERT INTO trilogy_test (binary_test, varbinary_test)
      VALUES ("hello", "world")
    SQL

    results = @client.query(<<-SQL).to_a
      SELECT binary_test, varbinary_test FROM trilogy_test
    SQL

    assert_equal [["hello\0\0\0\0\0".b, "world"]], results

    assert_equal [Encoding::BINARY, Encoding::BINARY], results[0].map(&:encoding)
  end

  def test_everything_else_casts_to_string
    value = "hello"

    text_columns = %w(
      char_test
      varchar_test
      tiny_text_test
      text_test
      medium_text_test
      long_text_test
    )

    text_columns.each do |column|
      create_test_table(@client)

      @client.query(<<-SQL)
        INSERT INTO trilogy_test (#{column})
        VALUES ("#{value}")
      SQL

      results = @client.query(<<-SQL).to_a
        SELECT #{column} FROM trilogy_test
      SQL

      assert_equal [[value]], results

      assert_equal Encoding::UTF_8, results[0][0].encoding
    end

    binary_columns = %w(
      varbinary_test
      tiny_blob_test
      blob_test
      medium_blob_test
      long_blob_test
    )

    binary_columns.each do |column|
      create_test_table(@client)

      @client.query(<<-SQL)
        INSERT INTO trilogy_test (#{column})
        VALUES ("#{value}")
      SQL

      results = @client.query(<<-SQL).to_a
        SELECT #{column} FROM trilogy_test
      SQL

      assert_equal [[value]], results

      assert_equal Encoding::ASCII_8BIT, results[0][0].encoding
    end

    member_columns = %w(enum_test set_test)

    value = "val1"

    member_columns.each do |column|
      create_test_table(@client)

      @client.query(<<-SQL)
        INSERT INTO trilogy_test (#{column})
        VALUES ("#{value}")
      SQL

      results = @client.query(<<-SQL).to_a
        SELECT #{column} FROM trilogy_test
      SQL

      assert_equal [[value]], results

      assert_equal Encoding::UTF_8, results[0][0].encoding
    end
  end

  def test_respects_database_encoding
    @client.query(<<-SQL)
      SET NAMES "SJIS"
    SQL

    results = @client.query(<<-SQL).to_a
      SELECT ""
    SQL

    assert_equal [[""]], results

    assert_equal Encoding::Shift_JIS, results[0][0].encoding
  end
end
