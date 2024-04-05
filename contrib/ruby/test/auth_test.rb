require "test_helper"

class AuthTest < TrilogyTest
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
