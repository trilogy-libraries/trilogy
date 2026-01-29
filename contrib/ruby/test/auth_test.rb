require "test_helper"

class AuthTest < TrilogyTest
  def setup
    # Only try to install cleartext plugin on MySQL (MariaDB doesn't have auth_test_plugin.so)
    if has_cleartext_plugin_available?
      client = new_tcp_client
      plugin_exists = client.query("SELECT name FROM mysql.plugin WHERE name = 'cleartext_plugin_server'").rows.first
      unless plugin_exists
        client.query("INSTALL PLUGIN cleartext_plugin_server SONAME 'auth_test_plugin.so'")
      end
    end

    super
  end

  def has_cleartext_plugin_available?
    # MariaDB doesn't ship auth_test_plugin.so, only MySQL does
    !is_mariadb?
  end

  def has_caching_sha2?
    server_version = new_tcp_client.server_version
    # MySQL 8+ has caching_sha2_password
    # MariaDB server-side caching_sha2_password was added in 12.1 (Community) / 11.8 (Enterprise)
    # Ref: https://mariadb.com/docs/server/reference/clientserver-protocol/1-connecting/caching_sha2_password-authentication-plugin
    if is_mariadb?
      # MariaDB version format is like "10.6.18-MariaDB" or "11.4.5-MariaDB"
      version_parts = server_version.split("-").first.split(".")
      major = version_parts[0].to_i
      # Only available in MariaDB 12.1+ for Community Server (we test against Community images)
      major >= 12
    else
      server_version.split(".", 2)[0].to_i >= 8
    end
  end

  def has_native_password_plugin?
    new_tcp_client.query("SELECT PLUGIN_NAME FROM information_schema.plugins WHERE PLUGIN_NAME = 'mysql_native_password'").count > 0
  rescue Trilogy::Error
    false
  end

  def test_connect_native_with_password
    return skip unless has_native_password_plugin?
    # mysql_native_password user creation has issues on MariaDB (connection reset during ALTER USER)
    return skip("mysql_native_password test not supported on MariaDB") if is_mariadb?
    create_and_delete_test_user(username: "native", auth_plugin: "mysql_native_password") do
      client = new_tcp_client username: "native", password: "password"

      refute_nil client
    ensure
      ensure_closed client
    end
  end

  def test_connect_caching_sha2_with_password
    return skip unless has_caching_sha2?
    create_and_delete_test_user(username: "caching_sha2", auth_plugin: "caching_sha2_password") do

      client = new_tcp_client username: "caching_sha2", password: "password"

      refute_nil client
    ensure
      ensure_closed client
    end
  end

  def test_connect_with_unix_and_caching_sha2_works
    return skip unless has_caching_sha2?
    return skip unless ["127.0.0.1", "localhost"].include?(DEFAULT_HOST)
    create_and_delete_test_user(username: "caching_sha2", host: "localhost", auth_plugin: "caching_sha2_password") do

      socket = new_tcp_client.query("SHOW VARIABLES LIKE 'socket'").to_a[0][1]

      if !File.exist?(socket)
        skip "cound not find socket at #{socket}"
      end

      client = new_unix_client(socket, username: "caching_sha2", password: "password")
      refute_nil client
    ensure
      ensure_closed client
    end
  end

  def test_connect_without_ssl_or_unix_socket_caching_sha2_works
    return skip unless has_caching_sha2?

    create_and_delete_test_user(username: "caching_sha2", auth_plugin: "caching_sha2_password") do
      client = nil
      options = {
        host: DEFAULT_HOST,
        port: DEFAULT_PORT,
        username: "caching_sha2",
        password: "password",
        ssl: false,
        ssl_mode: 0
      }

      client = new_tcp_client options

      refute_nil client
    ensure
      ensure_closed client
    end
  end

  def test_connect_without_ssl_caching_sha2_wrong_password
    return skip unless has_caching_sha2?

    create_and_delete_test_user(username: "caching_sha2", auth_plugin: "caching_sha2_password") do
      options = {
        host: DEFAULT_HOST,
        port: DEFAULT_PORT,
        username: "caching_sha2",
        password: "wrong",
        ssl: false,
        ssl_mode: 0
      }

      err = assert_raises Trilogy::ConnectionError do
        new_tcp_client options
      end

      assert_includes err.message, "Access denied for user 'caching_sha2"
    end
  end

  def test_connection_error_native
    return skip unless has_native_password_plugin?
    # mysql_native_password user creation has issues on MariaDB (connection reset during ALTER USER)
    return skip("mysql_native_password test not supported on MariaDB") if is_mariadb?
    create_and_delete_test_user(username: "native", auth_plugin: "mysql_native_password") do

      err = assert_raises Trilogy::ConnectionError do
        new_tcp_client(username: "native", password: "incorrect")
      end

      assert_includes err.message, "Access denied for user 'native"
    end
  end

  def test_connection_error_caching_sha2
    return skip unless has_caching_sha2?

    create_and_delete_test_user(username: "caching_sha2", auth_plugin: "caching_sha2_password") do

      err = assert_raises Trilogy::ConnectionError do
        new_tcp_client(username: "caching_sha2", password: "incorrect")
      end
      assert_includes err.message, "Access denied for user 'caching_sha2"
    end
  end

  def test_cleartext_auth_plugin_with_password
    return skip unless has_cleartext_plugin_available?
    create_and_delete_test_user(username: "cleartext_user", auth_plugin: "cleartext_plugin_server") do
      client = new_tcp_client username: "cleartext_user", password: "password", enable_cleartext_plugin: true
      refute_nil client
    ensure
      ensure_closed client
    end
  end

  def test_cleartext_auth_plugin_disabled
    return skip unless has_cleartext_plugin_available?
    create_and_delete_test_user(username: "cleartext_user", password: "", auth_plugin: "cleartext_plugin_server") do

      assert_raises Trilogy::AuthPluginError do
        new_tcp_client username: "cleartext_user", password: "password"
      end
    end
  end
end
