require "./spec_helper"

ALICE = {
  "cn"          => ["Alice"],
  "sn"          => ["Smith"],
  "mail"        => ["alice@example.com"],
  "objectClass" => ["person", "inetOrgPerson"],
  "uid"         => ["alice"],
}

BOB = {
  "cn"          => ["Bob"],
  "sn"          => ["Jones"],
  "mail"        => ["bob@example.com"],
  "objectClass" => ["person"],
  "uid"         => ["bob"],
}

describe LDAP::Server::Filter do
  describe "Equality" do
    it "matches exact value (case-insensitive)" do
      f = LDAP::Server::Filter::Equality.new("cn", "alice")
      f.matches?("cn=alice,dc=example", ALICE).should be_true
      f.matches?("cn=alice,dc=example", BOB).should be_false
    end

    it "is case-insensitive on value" do
      f = LDAP::Server::Filter::Equality.new("cn", "ALICE")
      f.matches?("cn=alice,dc=example", ALICE).should be_true
    end

    it "matches dn pseudo-attribute" do
      f = LDAP::Server::Filter::Equality.new("dn", "cn=alice,dc=example")
      f.matches?("cn=alice,dc=example", ALICE).should be_true
      f.matches?("cn=bob,dc=example", ALICE).should be_false
    end
  end

  describe "Present" do
    it "returns true when attribute exists" do
      f = LDAP::Server::Filter::Present.new("mail")
      f.matches?("cn=alice,dc=example", ALICE).should be_true
    end

    it "returns false when attribute absent" do
      f = LDAP::Server::Filter::Present.new("telephoneNumber")
      f.matches?("cn=alice,dc=example", ALICE).should be_false
    end

    it "objectClass is always present" do
      f = LDAP::Server::Filter::Present.new("objectClass")
      f.matches?("cn=alice,dc=example", {} of String => Array(String)).should be_true
    end
  end

  describe "And" do
    it "requires all sub-filters to match" do
      f = LDAP::Server::Filter::And.new([
        LDAP::Server::Filter::Equality.new("cn", "Alice"),
        LDAP::Server::Filter::Equality.new("sn", "Smith"),
      ] of LDAP::Server::Filter)
      f.matches?("cn=alice,dc=example", ALICE).should be_true
      f.matches?("cn=alice,dc=example", BOB).should be_false
    end
  end

  describe "Or" do
    it "requires at least one sub-filter to match" do
      f = LDAP::Server::Filter::Or.new([
        LDAP::Server::Filter::Equality.new("cn", "Alice"),
        LDAP::Server::Filter::Equality.new("cn", "Bob"),
      ] of LDAP::Server::Filter)
      f.matches?("cn=alice,dc=example", ALICE).should be_true
      f.matches?("cn=bob,dc=example", BOB).should be_true
    end
  end

  describe "Not" do
    it "inverts the sub-filter" do
      eq : LDAP::Server::Filter = LDAP::Server::Filter::Equality.new("cn", "Alice")
      f = LDAP::Server::Filter::Not.new(eq)
      f.matches?("cn=alice,dc=example", ALICE).should be_false
      f.matches?("cn=bob,dc=example", BOB).should be_true
    end
  end

  describe "Substring" do
    it "matches initial" do
      f = LDAP::Server::Filter::Substring.new("mail", "alice", [] of String, nil)
      f.matches?("cn=alice,dc=example", ALICE).should be_true
    end

    it "matches final" do
      f = LDAP::Server::Filter::Substring.new("mail", nil, [] of String, "example.com")
      f.matches?("cn=alice,dc=example", ALICE).should be_true
    end

    it "matches any" do
      f = LDAP::Server::Filter::Substring.new("mail", nil, ["@"], nil)
      f.matches?("cn=alice,dc=example", ALICE).should be_true
      f.matches?("cn=alice,dc=example", ALICE).should be_true
    end

    it "does not match when no value present" do
      f = LDAP::Server::Filter::Substring.new("mail", "bob", [] of String, nil)
      f.matches?("cn=alice,dc=example", ALICE).should be_false
    end
  end

  describe "GreaterOrEqual / LessOrEqual" do
    it "compares lexicographically" do
      ge = LDAP::Server::Filter::GreaterOrEqual.new("uid", "alice")
      ge.matches?("cn=bob,dc=example", BOB).should be_true # "bob" >= "alice"

      le = LDAP::Server::Filter::LessOrEqual.new("uid", "alice")
      le.matches?("cn=alice,dc=example", ALICE).should be_true
      le.matches?("cn=bob,dc=example", BOB).should be_false
    end
  end
end
