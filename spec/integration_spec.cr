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
    expected && expected == password ? LDAP::Response::Code::Success : LDAP::Response::Code::InvalidCredentials
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

# ── Mutable handler for CRUD tests ─────────────────────────────────────────────
#
# Each CRUD test gets its own fresh instance so mutations don't leak between tests.

class MutableHandler < LDAP::Server::Handler
  def initialize
    @dir = Hash(String, Hash(String, Array(String))).new
  end

  def entries : Hash(String, Hash(String, Array(String)))
    @dir
  end

  def on_bind(dn : String, password : String, conn : LDAP::Server::Connection) : LDAP::Response::Code
    LDAP::Response::Code::Success
  end

  def on_search(
    base : String,
    scope : LDAP::SearchScope,
    filter : LDAP::Server::Filter,
    attrs : Array(String),
    conn : LDAP::Server::Connection,
    &block : LDAP::Server::SearchEntry ->
  ) : LDAP::Response::Code
    @dir.each do |dn, entry_attrs|
      dl = dn.downcase; bl = base.downcase
      in_scope = case scope
                 when LDAP::SearchScope::BaseObject   then dl == bl
                 when LDAP::SearchScope::SingleLevel  then dl.split(",", 2)[1]? == bl
                 when LDAP::SearchScope::WholeSubtree then dl == bl || dl.ends_with?(",#{bl}")
                 else                                      false
                 end
      next unless in_scope
      next unless filter.matches?(dn, entry_attrs)
      block.call LDAP::Server::SearchEntry.new(dn, entry_attrs)
    end
    LDAP::Response::Code::Success
  end

  def on_add(dn : String, attributes : Hash(String, Array(String)), conn : LDAP::Server::Connection) : LDAP::Response::Code
    return LDAP::Response::Code::EntryAlreadyExists if @dir.has_key?(dn)
    @dir[dn] = attributes
    LDAP::Response::Code::Success
  end

  def on_delete(dn : String, conn : LDAP::Server::Connection) : LDAP::Response::Code
    return LDAP::Response::Code::NoSuchObject unless @dir.has_key?(dn)
    @dir.delete(dn)
    LDAP::Response::Code::Success
  end

  def on_modify(dn : String, changes : Array(LDAP::Server::Modification), conn : LDAP::Server::Connection) : LDAP::Response::Code
    entry = @dir[dn]?
    return LDAP::Response::Code::NoSuchObject unless entry

    changes.each do |mod|
      case mod.operation
      when LDAP::ModifyOperation::Add
        existing = entry[mod.attribute]? || [] of String
        entry[mod.attribute] = (existing + mod.values).uniq
      when LDAP::ModifyOperation::Delete
        if mod.values.empty?
          entry.delete(mod.attribute)
        else
          existing = entry[mod.attribute]? || [] of String
          entry[mod.attribute] = existing.reject { |v| mod.values.includes?(v) }
        end
      when LDAP::ModifyOperation::Replace
        entry[mod.attribute] = mod.values
      end
    end
    LDAP::Response::Code::Success
  end

  def on_modify_dn(dn : String, new_rdn : String, delete_old_rdn : Bool, new_superior : String?, conn : LDAP::Server::Connection) : LDAP::Response::Code
    entry = @dir.delete(dn)
    return LDAP::Response::Code::NoSuchObject unless entry

    # Build new DN from new_rdn + parent (or new_superior)
    parent = new_superior || dn.split(",", 2)[1]?
    new_dn = parent ? "#{new_rdn},#{parent}" : new_rdn

    # Update the RDN attribute in the entry
    rdn_attr, rdn_val = new_rdn.split("=", 2)
    if delete_old_rdn
      old_rdn_attr, old_rdn_val = dn.split("=", 2).map(&.strip)
      entry.delete(old_rdn_attr)
    end
    existing = entry[rdn_attr]? || [] of String
    entry[rdn_attr] = (existing + [rdn_val]).uniq

    @dir[new_dn] = entry
    LDAP::Response::Code::Success
  end

  def on_compare(dn : String, attribute : String, value : String, conn : LDAP::Server::Connection) : LDAP::Response::Code
    entry = @dir[dn]?
    return LDAP::Response::Code::NoSuchObject unless entry
    values = entry[attribute]?
    return LDAP::Response::Code::NoSuchAttribute unless values
    values.includes?(value) ? LDAP::Response::Code::CompareTrue : LDAP::Response::Code::CompareFalse
  end
end

def with_mutable_client(port : Int32, &block : LDAP::Client, MutableHandler ->)
  handler = MutableHandler.new
  server = LDAP::Server.new(handler, port: port)
  spawn server.listen
  Fiber.yield
  socket = TCPSocket.new("127.0.0.1", port)
  client = LDAP::Client.new(socket)
  client.authenticate("", "")
  begin
    block.call client, handler
  ensure
    client.close rescue nil
    server.close rescue nil
  end
end

# ── Extra handlers for specific lifecycle tests ────────────────────────────────

class BoundStateHandler < LDAP::Server::Handler
  property captured_bound : Bool = false
  property captured_dn : String = ""

  def on_bind(dn : String, password : String, conn : LDAP::Server::Connection) : LDAP::Response::Code
    dn == "cn=alice,dc=example,dc=com" && password == "alicepass" ? LDAP::Response::Code::Success : LDAP::Response::Code::InvalidCredentials
  end

  def on_search(base : String, scope : LDAP::SearchScope, filter : LDAP::Server::Filter,
                attrs : Array(String), conn : LDAP::Server::Connection,
                &block : LDAP::Server::SearchEntry ->) : LDAP::Response::Code
    @captured_bound = conn.bound?
    @captured_dn = conn.bound_dn
    LDAP::Response::Code::Success
  end
end

class UnbindTracker < LDAP::Server::Handler
  def initialize(@ch : Channel(Bool))
  end

  def on_bind(dn : String, password : String, conn : LDAP::Server::Connection) : LDAP::Response::Code
    LDAP::Response::Code::Success
  end

  def on_search(base : String, scope : LDAP::SearchScope, filter : LDAP::Server::Filter,
                attrs : Array(String), conn : LDAP::Server::Connection,
                &block : LDAP::Server::SearchEntry ->) : LDAP::Response::Code
    LDAP::Response::Code::Success
  end

  def on_unbind(conn : LDAP::Server::Connection) : Nil
    @ch.send(true)
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

  it "substring filter — ends_with" do
    with_client(port) do |c|
      c.authenticate("cn=admin,dc=example,dc=com", "admin123")
      results = c.search("dc=example,dc=com", LDAP::Request::Filter.ends("mail", "@example.com"))
      results.size.should eq 2
    end
    port += 1
  end

  it "substring filter — contains" do
    with_client(port) do |c|
      c.authenticate("cn=admin,dc=example,dc=com", "admin123")
      results = c.search("dc=example,dc=com", LDAP::Request::Filter.contains("mail", "bob"))
      results.size.should eq 1
      results.first["dn"].should eq ["cn=bob,dc=example,dc=com"]
    end
    port += 1
  end

  it "present filter — matches entries that have the attribute" do
    with_client(port) do |c|
      c.authenticate("cn=admin,dc=example,dc=com", "admin123")
      results = c.search("dc=example,dc=com", LDAP::Request::Filter.present?("mail"))
      results.size.should eq 2
    end
    port += 1
  end

  it "greater_than filter — matches sn >= K (Jones and Smith)" do
    with_client(port) do |c|
      c.authenticate("cn=admin,dc=example,dc=com", "admin123")
      # "Jones" >= "J" and "Smith" >= "J" — both should match
      results = c.search("dc=example,dc=com", LDAP::Request::Filter.greater_than("sn", "J"))
      results.size.should eq 2
    end
    port += 1
  end

  it "less_than filter — matches sn <= M (Jones only)" do
    with_client(port) do |c|
      c.authenticate("cn=admin,dc=example,dc=com", "admin123")
      # "Jones" <= "M" but "Smith" > "M"
      results = c.search("dc=example,dc=com", LDAP::Request::Filter.less_than("sn", "M"))
      results.size.should eq 1
      results.first["dn"].should eq ["cn=bob,dc=example,dc=com"]
    end
    port += 1
  end

  it "search returns empty result set (no match) with Success" do
    with_client(port) do |c|
      c.authenticate("cn=admin,dc=example,dc=com", "admin123")
      results = c.search("dc=example,dc=com", LDAP::Request::Filter.equal("uid", "nobody"))
      results.size.should eq 0
    end
    port += 1
  end

  it "wildcard attribute list (*) returns all attributes" do
    with_client(port) do |c|
      c.authenticate("cn=admin,dc=example,dc=com", "admin123")
      results = c.search(
        "dc=example,dc=com",
        LDAP::Request::Filter.equal("uid", "alice"),
        attributes: ["*"]
      )
      results.size.should eq 1
      entry = results.first
      entry.has_key?("cn").should be_true
      entry.has_key?("sn").should be_true
      entry.has_key?("mail").should be_true
      entry.has_key?("uid").should be_true
    end
    port += 1
  end

  it "conn.bound? and conn.bound_dn reflect authenticated state" do
    handler = BoundStateHandler.new

    server = LDAP::Server.new(handler, port: port)
    spawn server.listen
    Fiber.yield

    socket = TCPSocket.new("127.0.0.1", port)
    client = LDAP::Client.new(socket)
    client.authenticate("cn=alice,dc=example,dc=com", "alicepass")
    client.search("dc=example,dc=com", LDAP::Request::Filter.equal("objectClass", "*"))
    client.close rescue nil
    server.close rescue nil

    handler.captured_bound.should be_true
    handler.captured_dn.should eq "cn=alice,dc=example,dc=com"
    port += 1
  end

  it "on_unbind is called when the client disconnects" do
    unbind_called = Channel(Bool).new(1)
    handler = UnbindTracker.new(unbind_called)

    server = LDAP::Server.new(handler, port: port)
    spawn server.listen
    Fiber.yield

    socket = TCPSocket.new("127.0.0.1", port)
    client = LDAP::Client.new(socket)
    client.authenticate("", "")
    client.close rescue nil

    select
    when val = unbind_called.receive
      val.should be_true
    when timeout 2.seconds
      fail "on_unbind was not called within 2 seconds"
    end

    server.close rescue nil
    port += 1
  end
end

# ── CRUD integration tests ─────────────────────────────────────────────────────

describe "LDAP::Server CRUD operations" do
  port = 14000

  it "add creates a new entry" do
    with_mutable_client(port) do |c, h|
      c.add("cn=carol,dc=example,dc=com", {
        "cn"          => ["Carol"],
        "objectClass" => ["person"],
      })
      h.entries.has_key?("cn=carol,dc=example,dc=com").should be_true
      h.entries["cn=carol,dc=example,dc=com"]["cn"].should eq ["Carol"]
    end
    port += 1
  end

  it "add returns EntryAlreadyExists for a duplicate DN" do
    with_mutable_client(port) do |c, h|
      attrs = {"cn" => ["Carol"], "objectClass" => ["person"]}
      c.add("cn=carol,dc=example,dc=com", attrs)
      expect_raises(LDAP::Client::WriteError, /EntryAlreadyExists/i) do
        c.add("cn=carol,dc=example,dc=com", attrs)
      end
    end
    port += 1
  end

  it "delete removes an existing entry" do
    with_mutable_client(port) do |c, h|
      c.add("cn=dave,dc=example,dc=com", {"cn" => ["Dave"], "objectClass" => ["person"]})
      c.delete("cn=dave,dc=example,dc=com")
      h.entries.has_key?("cn=dave,dc=example,dc=com").should be_false
    end
    port += 1
  end

  it "delete returns NoSuchObject for a missing DN" do
    with_mutable_client(port) do |c, _|
      expect_raises(LDAP::Client::WriteError, /NoSuchObject/i) do
        c.delete("cn=nobody,dc=example,dc=com")
      end
    end
    port += 1
  end

  it "modify replace changes attribute values" do
    with_mutable_client(port) do |c, h|
      c.add("cn=eve,dc=example,dc=com", {"cn" => ["Eve"], "mail" => ["old@example.com"], "objectClass" => ["person"]})
      c.modify("cn=eve,dc=example,dc=com", [
        {LDAP::ModifyOperation::Replace, "mail", ["new@example.com"]},
      ])
      h.entries["cn=eve,dc=example,dc=com"]["mail"].should eq ["new@example.com"]
    end
    port += 1
  end

  it "modify add appends new values to an attribute" do
    with_mutable_client(port) do |c, h|
      c.add("cn=frank,dc=example,dc=com", {"cn" => ["Frank"], "objectClass" => ["person"]})
      c.modify("cn=frank,dc=example,dc=com", [
        {LDAP::ModifyOperation::Add, "objectClass", ["inetOrgPerson"]},
      ])
      h.entries["cn=frank,dc=example,dc=com"]["objectClass"].should contain "inetOrgPerson"
      h.entries["cn=frank,dc=example,dc=com"]["objectClass"].should contain "person"
    end
    port += 1
  end

  it "modify delete removes specific values from an attribute" do
    with_mutable_client(port) do |c, h|
      c.add("cn=grace,dc=example,dc=com", {"cn" => ["Grace"], "objectClass" => ["person", "inetOrgPerson"]})
      c.modify("cn=grace,dc=example,dc=com", [
        {LDAP::ModifyOperation::Delete, "objectClass", ["inetOrgPerson"]},
      ])
      h.entries["cn=grace,dc=example,dc=com"]["objectClass"].should eq ["person"]
    end
    port += 1
  end

  it "modify returns NoSuchObject for a missing DN" do
    with_mutable_client(port) do |c, _|
      expect_raises(LDAP::Client::WriteError, /NoSuchObject/i) do
        c.modify("cn=nobody,dc=example,dc=com", [
          {LDAP::ModifyOperation::Replace, "cn", ["X"]},
        ])
      end
    end
    port += 1
  end

  it "modify_dn renames an entry within the same parent" do
    with_mutable_client(port) do |c, h|
      c.add("cn=henry,dc=example,dc=com", {"cn" => ["Henry"], "objectClass" => ["person"]})
      c.modify_dn("cn=henry,dc=example,dc=com", "cn=hank", true)
      h.entries.has_key?("cn=henry,dc=example,dc=com").should be_false
      h.entries.has_key?("cn=hank,dc=example,dc=com").should be_true
      h.entries["cn=hank,dc=example,dc=com"]["cn"].should contain "hank"
    end
    port += 1
  end

  it "modify_dn moves an entry to a new superior" do
    with_mutable_client(port) do |c, h|
      c.add("cn=ivan,dc=example,dc=com", {"cn" => ["Ivan"], "objectClass" => ["person"]})
      c.modify_dn("cn=ivan,dc=example,dc=com", "cn=ivan", true, "ou=staff,dc=example,dc=com")
      h.entries.has_key?("cn=ivan,dc=example,dc=com").should be_false
      h.entries.has_key?("cn=ivan,ou=staff,dc=example,dc=com").should be_true
    end
    port += 1
  end

  it "compare returns true when attribute value matches" do
    with_mutable_client(port) do |c, _|
      c.add("cn=judy,dc=example,dc=com", {"cn" => ["Judy"], "objectClass" => ["person"]})
      c.compare("cn=judy,dc=example,dc=com", "cn", "Judy").should be_true
    end
    port += 1
  end

  it "compare returns false when attribute value does not match" do
    with_mutable_client(port) do |c, _|
      c.add("cn=karl,dc=example,dc=com", {"cn" => ["Karl"], "objectClass" => ["person"]})
      c.compare("cn=karl,dc=example,dc=com", "cn", "NotKarl").should be_false
    end
    port += 1
  end

  it "compare raises on NoSuchObject" do
    with_mutable_client(port) do |c, _|
      expect_raises(LDAP::Client::WriteError, /NoSuchObject/i) do
        c.compare("cn=nobody,dc=example,dc=com", "cn", "x")
      end
    end
    port += 1
  end

  it "added entry is immediately searchable" do
    with_mutable_client(port) do |c, _|
      c.add("cn=lena,dc=example,dc=com", {"cn" => ["Lena"], "uid" => ["lena"], "objectClass" => ["person"]})
      results = c.search("dc=example,dc=com", LDAP::Request::Filter.equal("uid", "lena"))
      results.size.should eq 1
      results.first["dn"].should eq ["cn=lena,dc=example,dc=com"]
    end
    port += 1
  end

  it "deleted entry no longer appears in search" do
    with_mutable_client(port) do |c, _|
      c.add("cn=mike,dc=example,dc=com", {"cn" => ["Mike"], "uid" => ["mike"], "objectClass" => ["person"]})
      c.delete("cn=mike,dc=example,dc=com")
      results = c.search("dc=example,dc=com", LDAP::Request::Filter.equal("uid", "mike"))
      results.size.should eq 0
    end
    port += 1
  end
end
