require "./spec_helper"
require "ldap/client"

# ── In-memory directory ────────────────────────────────────────────────────────

DIRECTORY = {
  "cn=alice,dc=example,dc=com" => {
    "cn"          => ["Alice"],
    "sn"          => ["Smith"],
    "uid"         => ["alice"],
    "mail"        => ["alice@example.com"],
    "objectClass" => ["person", "inetOrgPerson"],
  },
  "cn=bob,dc=example,dc=com" => {
    "cn"          => ["Bob"],
    "sn"          => ["Jones"],
    "uid"         => ["bob"],
    "mail"        => ["bob@example.com"],
    "objectClass" => ["person"],
  },
}

CREDENTIALS = {
  "cn=admin,dc=example,dc=com" => "admin123",
  "cn=alice,dc=example,dc=com" => "alicepass",
}

class TestHandler < LDAP::Server::Handler
  def on_bind(dn : String, password : String, conn : LDAP::Server::Connection) : LDAP::Response::Code
    return LDAP::Response::Code::Success if dn.empty? # anonymous bind always allowed
    expected = CREDENTIALS[dn]?
    expected && expected == password ? LDAP::Response::Code::Success
                                     : LDAP::Response::Code::InvalidCredentials
  end

  def on_search(
    base : String,
    scope : LDAP::SearchScope,
    filter : LDAP::Server::Filter,
    attrs : Array(String),
    conn : LDAP::Server::Connection,
    &block : LDAP::Server::SearchEntry ->
  ) : LDAP::Response::Code
    DIRECTORY.each do |dn, entry_attrs|
      next unless under_base?(dn, base, scope)
      next unless filter.matches?(dn, entry_attrs)
      block.call LDAP::Server::SearchEntry.new(dn, entry_attrs)
    end
    LDAP::Response::Code::Success
  end

  private def under_base?(dn : String, base : String, scope : LDAP::SearchScope) : Bool
    dl = dn.downcase
    bl = base.downcase
    case scope
    when LDAP::SearchScope::BaseObject
      dl == bl
    when LDAP::SearchScope::SingleLevel
      parent = dl.split(",", 2)[1]?
      parent == bl
    when LDAP::SearchScope::WholeSubtree
      dl == bl || dl.ends_with?(",#{bl}")
    else
      false
    end
  end
end

# ── Test helper ────────────────────────────────────────────────────────────────

# The TCPServer is bound in LDAP::Server's constructor, so the port is ready
# before `listen` is called.  We spawn the listen loop, yield once so the
# fiber scheduler has a chance to run, then connect.
def with_client(port : Int32, &block : LDAP::Client ->)
  server = LDAP::Server.new(TestHandler.new, port: port)
  spawn server.listen
  Fiber.yield

  socket = TCPSocket.new("127.0.0.1", port)
  client = LDAP::Client.new(socket)
  begin
    block.call client
  ensure
    client.close rescue nil
    server.close rescue nil
  end
end

# ── Integration tests ──────────────────────────────────────────────────────────

describe "LDAP::Server (integration via crystal-ldap client)" do
  # Use a fresh port for every test to avoid TIME_WAIT overlap.
  port = 13890

  it "accepts anonymous bind (empty dn + password)" do
    with_client(port) { |c| c.authenticate("", "") }
    port += 1
  end

  it "accepts a valid bind" do
    with_client(port) { |c| c.authenticate("cn=admin,dc=example,dc=com", "admin123") }
    port += 1
  end

  it "rejects wrong password" do
    expect_raises(LDAP::Client::AuthError, /InvalidCredentials/i) do
      with_client(port) { |c| c.authenticate("cn=admin,dc=example,dc=com", "wrong") }
    end
    port += 1
  end

  it "returns all entries for (objectClass=*)" do
    with_client(port) do |c|
      c.authenticate("cn=admin,dc=example,dc=com", "admin123")
      results = c.search("dc=example,dc=com", LDAP::Request::Filter.equal("objectClass", "*"))
      results.size.should eq 2
    end
    port += 1
  end

  it "filters by equality — finds alice" do
    with_client(port) do |c|
      c.authenticate("cn=admin,dc=example,dc=com", "admin123")
      results = c.search("dc=example,dc=com", LDAP::Request::Filter.equal("cn", "Alice"))
      results.size.should eq 1
      results.first["dn"].should eq ["cn=alice,dc=example,dc=com"]
      results.first["cn"].should eq ["Alice"]
      results.first["sn"].should eq ["Smith"]
    end
    port += 1
  end

  it "filters by equality — finds bob" do
    with_client(port) do |c|
      c.authenticate("cn=admin,dc=example,dc=com", "admin123")
      results = c.search("dc=example,dc=com", LDAP::Request::Filter.equal("uid", "bob"))
      results.size.should eq 1
      results.first["dn"].should eq ["cn=bob,dc=example,dc=com"]
    end
    port += 1
  end

  it "parses string filter syntax" do
    with_client(port) do |c|
      c.authenticate("cn=admin,dc=example,dc=com", "admin123")
      results = c.search("dc=example,dc=com", "(uid=alice)")
      results.size.should eq 1
      results.first["dn"].should eq ["cn=alice,dc=example,dc=com"]
    end
    port += 1
  end

  it "handles compound AND filter" do
    with_client(port) do |c|
      c.authenticate("cn=admin,dc=example,dc=com", "admin123")
      filter = LDAP::Request::Filter.equal("objectClass", "inetOrgPerson") &
               LDAP::Request::Filter.equal("uid", "alice")
      results = c.search("dc=example,dc=com", filter)
      results.size.should eq 1
      results.first["dn"].should eq ["cn=alice,dc=example,dc=com"]
    end
    port += 1
  end

  it "handles OR filter" do
    with_client(port) do |c|
      c.authenticate("cn=admin,dc=example,dc=com", "admin123")
      filter = LDAP::Request::Filter.equal("uid", "alice") |
               LDAP::Request::Filter.equal("uid", "bob")
      results = c.search("dc=example,dc=com", filter)
      results.size.should eq 2
    end
    port += 1
  end

  it "handles NOT filter — excludes alice" do
    with_client(port) do |c|
      c.authenticate("cn=admin,dc=example,dc=com", "admin123")
      filter = ~LDAP::Request::Filter.equal("uid", "alice")
      results = c.search("dc=example,dc=com", filter)
      results.size.should eq 1
      results.first["dn"].should eq ["cn=bob,dc=example,dc=com"]
    end
    port += 1
  end

  it "BaseObject scope returns only the base entry" do
    with_client(port) do |c|
      c.authenticate("cn=admin,dc=example,dc=com", "admin123")
      results = c.search(
        "cn=alice,dc=example,dc=com",
        LDAP::Request::Filter.equal("objectClass", "*"),
        scope: LDAP::SearchScope::BaseObject
      )
      results.size.should eq 1
      results.first["dn"].should eq ["cn=alice,dc=example,dc=com"]
    end
    port += 1
  end

  it "SingleLevel scope returns only direct children" do
    with_client(port) do |c|
      c.authenticate("cn=admin,dc=example,dc=com", "admin123")
      results = c.search(
        "dc=example,dc=com",
        LDAP::Request::Filter.equal("objectClass", "*"),
        scope: LDAP::SearchScope::SingleLevel
      )
      results.size.should eq 2
    end
    port += 1
  end

  it "attribute projection — only requested attributes returned" do
    with_client(port) do |c|
      c.authenticate("cn=admin,dc=example,dc=com", "admin123")
      results = c.search(
        "dc=example,dc=com",
        LDAP::Request::Filter.equal("uid", "alice"),
        attributes: ["cn", "mail"]
      )
      results.size.should eq 1
      entry = results.first
      entry.has_key?("cn").should be_true
      entry.has_key?("mail").should be_true
      entry.has_key?("sn").should be_false
      entry.has_key?("uid").should be_false
    end
    port += 1
  end

  it "substring filter — begins_with" do
    with_client(port) do |c|
      c.authenticate("cn=admin,dc=example,dc=com", "admin123")
      results = c.search("dc=example,dc=com", LDAP::Request::Filter.begins("mail", "alice"))
      results.size.should eq 1
      results.first["dn"].should eq ["cn=alice,dc=example,dc=com"]
    end
    port += 1
  end
end
