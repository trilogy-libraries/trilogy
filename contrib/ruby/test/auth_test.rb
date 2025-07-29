require "test_helper"

class AuthTest < TrilogyTest
  def setup
    client = new_tcp_client

    plugin_exists = client.query("SELECT name FROM mysql.plugin WHERE name = 'cleartext_plugin_server'").rows.first
    unless plugin_exists
      client.query("INSTALL PLUGIN cleartext_plugin_server SONAME 'auth_test_plugin.so'")
    end

    super
  end

  def has_caching_sha2?
    server_version = new_tcp_client.server_version
    server_version.split(".", 2)[0].to_i >= 8
  end

  def test_connect_native_with_password
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

      # Ensure correct setup
      assert_equal [["caching_sha2_password"]], new_tcp_client.query("SELECT plugin FROM mysql.user WHERE user = 'caching_sha2'").rows

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

  def test_connect_without_ssl_or_unix_socket_caching_sha2_raises
    return skip unless has_caching_sha2?

    create_and_delete_test_user(username: "caching_sha2", auth_plugin: "caching_sha2_password") do
      # Ensure correct setup
      assert_equal [["caching_sha2_password"]], new_tcp_client.query("SELECT plugin FROM mysql.user WHERE user = 'caching_sha2'").rows

      options = {
        host: DEFAULT_HOST,
        port: DEFAULT_PORT,
        username: "caching_sha2",
        password: "password",
        ssl: false,
        ssl_mode: 0
      }

      err = assert_raises Trilogy::ConnectionError do
        new_tcp_client options
      end

      assert_includes err.message, "TRILOGY_UNSUPPORTED"
      assert_includes err.message, "caching_sha2_password requires either TCP with TLS or a unix socket"
    end
  end

  def test_connection_error_native
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
    create_and_delete_test_user(username: "cleartext_user", auth_plugin: "cleartext_plugin_server") do
      client = new_tcp_client username: "cleartext_user", password: "password", enable_cleartext_plugin: true
      refute_nil client
    ensure
      ensure_closed client
    end
  end

  def test_cleartext_auth_plugin_disabled
    create_and_delete_test_user(username: "cleartext_user", password: "", auth_plugin: "cleartext_plugin_server") do

      assert_raises Trilogy::AuthPluginError do
        new_tcp_client username: "cleartext_user", password: "password"
      end
    end
  end
end
