require "test_helper"

class AuthTest < TrilogyTest
  def has_caching_sha2?
    server_version = new_tcp_client.server_version
    server_version.split(".", 2)[0].to_i >= 8
  end

  def test_connect_native_password
    client = new_tcp_client username: "native"

    refute_nil client
  ensure
    ensure_closed client
  end

  def test_connect_caching_sha2
    return skip unless has_caching_sha2?

    # Ensure correct setup
    assert_equal [["caching_sha2_password"]], new_tcp_client.query("SELECT plugin FROM mysql.user WHERE user = 'caching_sha2'").rows

    client = new_tcp_client username: "caching_sha2", password: "password"

    refute_nil client
  ensure
    ensure_closed client
  end

  def test_connect_with_unix_and_caching_sha2_works
    return skip unless has_caching_sha2?
    return skip unless ["127.0.0.1", "localhost"].include?(DEFAULT_HOST)

    socket = new_tcp_client.query("SHOW VARIABLES LIKE 'socket'").to_a[0][1]

    if !File.exist?(socket)
      skip "cound not find socket at #{socket}"
    end

    client = new_unix_client(socket, username: "caching_sha2", password: "password")
    refute_nil client
  ensure
    ensure_closed client
  end

  def test_connect_without_ssl_or_unix_socket_caching_sha2_raises
    return skip unless has_caching_sha2?

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

  def test_connection_error_native
    err = assert_raises Trilogy::ConnectionError do
      new_tcp_client(username: "native", password: "incorrect")
    end
    assert_includes err.message, "Access denied for user 'native"
  end

  def test_connection_error_caching_sha2
    return skip unless has_caching_sha2?

    err = assert_raises Trilogy::ConnectionError do
      new_tcp_client(username: "caching_sha2", password: "incorrect")
    end
    assert_includes err.message, "Access denied for user 'caching_sha2"
  end

  def test_cleartext_auth_plugin
    client = new_tcp_client username: "cleartext_user", password: "password", enable_cleartext_plugin: true
    refute_nil client
  ensure
    ensure_closed client
  end

  def test_cleartext_auth_plugin_disabled
    assert_raises Trilogy::AuthPluginError do
      new_tcp_client username: "cleartext_user", password: "password"
    end
  end
end
