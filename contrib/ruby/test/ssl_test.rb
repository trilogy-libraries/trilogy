require "test_helper"

require "openssl"
require "trilogy"
require "timeout"
require "resolv"

class SslTest < TrilogyTest
  def setup
    super

    if server_global_variable("have_ssl") != "YES"
      skip "SSL is disabled on the server"
    end
  end

  def tcp_client_defaults
    super.merge(ssl_mode: Trilogy::SSL_REQUIRED_NOVERIFY)
  end

  def server_supported_tls_versions
    server_global_variable("tls_version").split(",")
  end

  def tls_1_3_support?
    server_support = server_supported_tls_versions.include?("TLSv1.3")
    client_support = defined?(OpenSSL::SSL::TLS1_3_VERSION)
    server_support && client_support
  end

  def test_trilogy_connect_db_without_ssl
    client = new_tcp_client(database: "test", ssl: false)
    result = client.query "SELECT DATABASE()"
    assert_equal [["test"]], result.to_a
  ensure
    ensure_closed client
  end

  def test_trilogy_connect_db_with_ssl
    client = new_tcp_client(database: "test", ssl: true)
    result = client.query "SELECT DATABASE()"
    assert_equal [["test"]], result.to_a
  ensure
    ensure_closed client
  end

  def test_trilogy_connect_ssl_config_tls12
    client = new_tcp_client(database: "test", ssl: true, tls_min_version: Trilogy::TLS_VERSION_12, tls_max_version: Trilogy::TLS_VERSION_12)
    result = client.query "SELECT * FROM performance_schema.session_status WHERE VARIABLE_NAME = 'Ssl_version'"
    assert_equal [["Ssl_version", "TLSv1.2"]], result.to_a
  ensure
    ensure_closed client
  end

  def test_trilogy_connect_ssl_config_tls13
    return skip unless tls_1_3_support?

    client = new_tcp_client(database: "test", ssl: true, tls_min_version: Trilogy::TLS_VERSION_13, tls_max_version: Trilogy::TLS_VERSION_13)
    result = client.query "SELECT * FROM performance_schema.session_status WHERE VARIABLE_NAME = 'Ssl_version'"
    assert_equal [["Ssl_version", "TLSv1.3"]], result.to_a
  ensure
    ensure_closed client
  end

  def test_trilogy_connect_ssl_config_cipher_tls13_aesgcm128
    return skip unless tls_1_3_support?

    client = new_tcp_client(database: "test", ssl: true, tls_min_version: Trilogy::TLS_VERSION_13, tls_max_version: Trilogy::TLS_VERSION_13, tls_ciphersuites: "TLS_AES_128_GCM_SHA256")
    result = client.query "SELECT * FROM performance_schema.session_status WHERE VARIABLE_NAME = 'Ssl_cipher'"
    assert_equal [["Ssl_cipher", "TLS_AES_128_GCM_SHA256"]], result.to_a
  ensure
    ensure_closed client
  end

  def test_trilogy_connect_ssl_config_cipher_tls13_aesgcm256
    return skip unless tls_1_3_support?

    client = new_tcp_client(database: "test", ssl: true, tls_min_version: Trilogy::TLS_VERSION_13, tls_max_version: Trilogy::TLS_VERSION_13, tls_ciphersuites: "TLS_AES_256_GCM_SHA384")
    result = client.query "SELECT * FROM performance_schema.session_status WHERE VARIABLE_NAME = 'Ssl_cipher'"
    assert_equal [["Ssl_cipher", "TLS_AES_256_GCM_SHA384"]], result.to_a
  ensure
    ensure_closed client
  end

  def test_trilogy_connect_ssl_config_tls10
    return skip if server_supported_tls_versions.include?("TLSv1.1")

    err = assert_raises Trilogy::Error do
      new_tcp_client(database: "test", ssl: true, tls_min_version: Trilogy::TLS_VERSION_10,
                            tls_max_version: Trilogy::TLS_VERSION_10, ssl_cipher: "ECDHE-RSA-AES128-SHA")
    end
    assert_includes err.message, "protocol"
  end

  def test_trilogy_connect_ssl_config_cipher_aesgcm128
    client = new_tcp_client(database: "test", ssl: true, tls_max_version: Trilogy::TLS_VERSION_12, ssl_cipher: "ECDHE-RSA-AES128-GCM-SHA256")
    result = client.query "SELECT * FROM performance_schema.session_status WHERE VARIABLE_NAME = 'Ssl_cipher'"
    assert_equal [["Ssl_cipher", "ECDHE-RSA-AES128-GCM-SHA256"]], result.to_a
  ensure
    ensure_closed client
  end

  def test_trilogy_connect_ssl_config_cipher_aesgcm256
    client = new_tcp_client(database: "test", ssl: true, tls_max_version: Trilogy::TLS_VERSION_12, ssl_cipher: "ECDHE-RSA-AES256-GCM-SHA384")
    result = client.query "SELECT * FROM performance_schema.session_status WHERE VARIABLE_NAME = 'Ssl_cipher'"
    assert_equal [["Ssl_cipher", "ECDHE-RSA-AES256-GCM-SHA384"]], result.to_a
  ensure
    ensure_closed client
  end

  def test_trilogy_connect_ssl_type
    err = assert_raises Trilogy::Error do
      new_tcp_client(database: "test", ssl: true, ssl_cipher: "1234", tls_max_version: Trilogy::TLS_VERSION_12)
    end
    assert_includes err.message, "SSL Error: no cipher"
  end

  def test_raise_proper_invalid_ssl_state
    client = new_tcp_client(ssl: true)

    pid = fork do
      assert_equal [[1]], client.query("SELECT 1").to_a
      sleep 60
    end

    sleep 0.1

    err = assert_raises Trilogy::Error do
      client.query "SELECT 1"
    end
    assert_includes err.message, "SSL Error"

    # Socket is closed on this attempt due to previous failures.
    assert_raises_connection_error do
      client.query "SELECT 1"
    end

  ensure
    Process.kill("QUIT", pid)
    Process.wait(pid)

    ensure_closed client
  end

  def ca_cert_path
    path = ENV["TRILOGY_TEST_CERTS"]
    path if path && File.exist?("#{path}/ca.pem")
  end

  def test_trilogy_ssl_verify_ca_without_ca
    err = assert_raises Trilogy::Error do
      new_tcp_client(database: "test", ssl_mode: Trilogy::SSL_VERIFY_CA, tls_max_version: Trilogy::TLS_VERSION_12)
    end
    assert_includes err.message, "SSL Error: certificate verify failed"
  end

  def test_trilogy_ssl_verify_ca_with_ca
    return skip unless ca_cert_path

    client = new_tcp_client(database: "test", ssl_mode: Trilogy::SSL_VERIFY_CA, ssl_ca: "#{ca_cert_path}/ca.pem", tls_max_version: Trilogy::TLS_VERSION_12)
    result = client.query "SELECT * FROM performance_schema.session_status WHERE VARIABLE_NAME = 'Ssl_version'"
    assert_equal [["Ssl_version", "TLSv1.2"]], result.to_a
  ensure
    ensure_closed client
  end

  def test_trilogy_ssl_verify_identity_without_hostname_match
    return skip unless ca_cert_path

    # Use the IP of the host that's not in the server cert
    ip = Resolv.getaddress(DEFAULT_HOST)
    err = assert_raises Trilogy::Error do
      new_tcp_client(host: ip, database: "test", ssl_mode: Trilogy::SSL_VERIFY_IDENTITY, ssl_ca: "#{ca_cert_path}/ca.pem", tls_max_version: Trilogy::TLS_VERSION_12)
    end
    assert_includes err.message, "SSL Error: certificate verify failed"
  end

  def test_trilogy_ssl_verify_identity_with_hostname_match
    return skip unless ca_cert_path

    client = new_tcp_client(database: "test", ssl_mode: Trilogy::SSL_VERIFY_IDENTITY, ssl_ca: "#{ca_cert_path}/ca.pem", tls_max_version: Trilogy::TLS_VERSION_12)
    result = client.query "SELECT * FROM performance_schema.session_status WHERE VARIABLE_NAME = 'Ssl_version'"
    assert_equal [["Ssl_version", "TLSv1.2"]], result.to_a
  ensure
    ensure_closed client
  end

  def test_trilogy_ssl_verify_identity_with_hostname_wildcard_match
    return skip unless ca_cert_path

    client = new_tcp_client(host: "wildcard.#{DEFAULT_HOST}", database: "test", ssl_mode: Trilogy::SSL_VERIFY_IDENTITY, ssl_ca: "#{ca_cert_path}/ca.pem", tls_max_version: Trilogy::TLS_VERSION_12)
    result = client.query "SELECT * FROM performance_schema.session_status WHERE VARIABLE_NAME = 'Ssl_version'"
    assert_equal [["Ssl_version", "TLSv1.2"]], result.to_a
  ensure
    ensure_closed client
  end

  def test_trilogy_ssl_client_key
    return skip unless ca_cert_path

    err = assert_raises Trilogy::Error do
      new_tcp_client(username: "x509", database: "test", ssl_mode: Trilogy::SSL_VERIFY_IDENTITY,
                     ssl_ca: "#{ca_cert_path}/ca.pem", ssl_key: "#{ca_cert_path}/client-key.pem")
    end
    assert_includes err.message, "SSL Error: no certificate assigned"
  end

  def test_trilogy_ssl_client_cert
    return skip unless ca_cert_path

    err = assert_raises Trilogy::Error do
      new_tcp_client(username: "x509", database: "test", ssl_mode: Trilogy::SSL_VERIFY_IDENTITY,
                     ssl_ca: "#{ca_cert_path}/ca.pem", ssl_cert: "#{ca_cert_path}/client-cert.pem")
    end
    assert_includes err.message, "SSL Error: no private key assigned"
  end

  def test_trilogy_ssl_client_key_and_cert_mismatch
    return skip unless ca_cert_path

    err = assert_raises Trilogy::Error do
      new_tcp_client(username: "x509", database: "test", ssl_mode: Trilogy::SSL_VERIFY_IDENTITY,
                     ssl_ca: "#{ca_cert_path}/ca.pem", ssl_key: "#{ca_cert_path}/client-key.pem",
                     ssl_cert: "#{ca_cert_path}/server-cert.pem")
    end
    assert_includes err.message, "SSL Error: no private key assigned"
  end

  def test_trilogy_ssl_client_key_and_cert_match
    return skip unless ca_cert_path

    client = new_tcp_client(username: "x509", database: "test", ssl_mode: Trilogy::SSL_VERIFY_IDENTITY,
                            ssl_ca: "#{ca_cert_path}/ca.pem", ssl_key: "#{ca_cert_path}/client-key.pem",
                            ssl_cert: "#{ca_cert_path}/client-cert.pem")
    result = client.query "SELECT CURRENT_USER()"
    assert_equal [["x509@%"]], result.to_a
  ensure
    ensure_closed client
  end
end

# Separate from SslTest because its setup skips everything on non-SSL servers,
# while the fallback test here must run exactly then.
class DefaultSslModeTest < TrilogyTest
  # Not new_tcp_client, which passes ssl_mode explicitly and would mask the default.
  def direct_client(opts = {})
    Trilogy.new({
      host: DEFAULT_HOST,
      port: DEFAULT_PORT,
      username: DEFAULT_USER,
      password: DEFAULT_PASS,
    }.merge(opts))
  end

  # SHOW SESSION STATUS rather than performance_schema.session_status: the
  # latter is empty on servers running with performance_schema = OFF (e.g.
  # MariaDB < 11.4 defaults), where the fallback test below still needs to run.
  def ssl_cipher(client)
    result = client.query "SHOW SESSION STATUS LIKE 'Ssl_cipher'"
    result.to_a[0][1]
  end

  def server_supports_ssl?
    have_ssl = server_global_variable("have_ssl")
    return have_ssl == "YES" unless have_ssl.nil?

    # have_ssl was removed in MySQL 8.4+; check whether a server certificate is loaded instead
    client = direct_client(ssl_mode: Trilogy::SSL_DISABLED)
    status = client.query("SHOW GLOBAL STATUS LIKE 'Ssl_server_not_after'").to_a
    !status.empty? && !status[0][1].to_s.empty?
  ensure
    ensure_closed client
  end

  def test_default_ssl_mode_uses_tls_when_server_supports_it
    skip "SSL is disabled on the server" unless server_supports_ssl?

    client = direct_client
    refute_equal "", ssl_cipher(client)
  ensure
    ensure_closed client
  end

  def test_explicit_ssl_disabled_connects_without_tls
    skip "SSL is disabled on the server" unless server_supports_ssl?

    client = direct_client(ssl_mode: Trilogy::SSL_DISABLED)
    assert_equal "", ssl_cipher(client)
  ensure
    ensure_closed client
  end

  def test_default_ssl_mode_falls_back_to_plaintext_without_server_ssl
    skip "SSL is enabled on the server" if server_supports_ssl?

    client = direct_client
    assert_equal "", ssl_cipher(client)
  ensure
    ensure_closed client
  end

  def test_default_ssl_mode_does_not_apply_to_unix_socket
    return skip unless ["127.0.0.1", "localhost"].include?(DEFAULT_HOST)

    socket = new_tcp_client.query("SHOW VARIABLES LIKE 'socket'").to_a[0][1]

    if !File.exist?(socket)
      skip "could not find socket at #{socket}"
    end

    client = Trilogy.new(username: DEFAULT_USER, password: DEFAULT_PASS, socket: socket)
    assert_equal "", ssl_cipher(client)
  ensure
    ensure_closed client
  end
end
