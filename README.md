# ldap-server.cr

> **This shard was entirely written by [Claude](https://claude.ai) (Anthropic's AI assistant).**

A Crystal shard for building LDAP servers. Handles the protocol layer (BER/ASN.1 framing, message dispatch, response encoding) so you can focus on directory logic.

Built on top of [crystal-ldap](https://github.com/dirless/crystal-ldap), reusing its BER primitives, tag definitions, and filter infrastructure.

## Features

- TCP server with one fiber per client
- Simple, abstract `Handler` class — implement `on_bind` and `on_search`, optionally override CRUD methods
- Full RFC 4511 filter tree parsed from BER (AND, OR, NOT, equality, substring, present, ≥, ≤) with optional in-memory `matches?`
- Complete LDAP operation support: Bind, Search, Add, Delete, Modify, ModifyDN, Compare, Unbind, Abandon, StartTLS
- Works with any LDAP client (tested with [crystal-ldap](https://github.com/dirless/crystal-ldap), [ldapsearch](https://linux.die.net/man/1/ldapsearch))

## Installation

Add to your `shard.yml`:

```yaml
dependencies:
  ldap-server:
    github: dirless/ldap-server.cr
```

Then run `shards install`.

## Quick start

```crystal
require "ldap-server"

# In-memory directory
ENTRIES = Hash(String, Hash(String, Array(String))).new

class MyHandler < LDAP::Server::Handler
  def on_bind(dn : String, password : String, conn : LDAP::Server::Connection) : LDAP::Response::Code
    return LDAP::Response::Code::Success if dn.empty?           # anonymous bind
    return LDAP::Response::Code::Success if password == "secret"
    LDAP::Response::Code::InvalidCredentials
  end

  def on_search(
    base : String,
    scope : LDAP::SearchScope,
    filter : LDAP::Server::Filter,
    attrs : Array(String),
    conn : LDAP::Server::Connection,
    &block : LDAP::Server::SearchEntry ->
  ) : LDAP::Response::Code
    ENTRIES.each do |dn, entry_attrs|
      next unless dn.downcase.ends_with?(base.downcase)
      next unless filter.matches?(dn, entry_attrs)
      block.call LDAP::Server::SearchEntry.new(dn, entry_attrs)
    end
    LDAP::Response::Code::Success
  end

  def on_add(dn : String, attributes : Hash(String, Array(String)), conn : LDAP::Server::Connection) : LDAP::Response::Code
    return LDAP::Response::Code::EntryAlreadyExists if ENTRIES.has_key?(dn)
    ENTRIES[dn] = attributes
    LDAP::Response::Code::Success
  end

  def on_delete(dn : String, conn : LDAP::Server::Connection) : LDAP::Response::Code
    return LDAP::Response::Code::NoSuchObject unless ENTRIES.has_key?(dn)
    ENTRIES.delete(dn)
    LDAP::Response::Code::Success
  end
end

server = LDAP::Server.new(MyHandler.new, port: 1389)
server.listen   # blocks; each client runs in its own fiber
```

Test it with `ldapsearch`:

```sh
ldapsearch -H ldap://localhost:1389 -x -b "dc=example,dc=com" "(uid=alice)"
```

## API

### `LDAP::Server`

```crystal
server = LDAP::Server.new(handler, host: "0.0.0.0", port: 389)
server.listen   # accept loop (blocking)
server.close    # stop accepting
```

The port is bound when the `Server` object is constructed (before `listen` is called), so you can connect immediately after creation in tests.

### `LDAP::Server::Handler`

Subclass and override. `on_bind` and `on_search` are abstract (required); all other methods have sensible defaults (`UnwillingToPerform` for CRUD, no-op for unbind).

```crystal
abstract class LDAP::Server::Handler
  # ── Required ──────────────────────────────────────────────────────────

  # Return Success to accept the bind, or an error code to reject it.
  abstract def on_bind(dn, password, conn) : LDAP::Response::Code

  # Yield matching SearchEntry objects; return the final result code.
  abstract def on_search(base, scope, filter, attrs, conn, &block : SearchEntry ->) : LDAP::Response::Code

  # ── Optional (override to enable) ────────────────────────────────────

  # Add a new entry. Default: UnwillingToPerform.
  def on_add(dn, attributes, conn) : LDAP::Response::Code

  # Delete an entry. Default: UnwillingToPerform.
  def on_delete(dn, conn) : LDAP::Response::Code

  # Modify an entry's attributes. Default: UnwillingToPerform.
  def on_modify(dn, changes : Array(Modification), conn) : LDAP::Response::Code

  # Rename or move an entry. Default: UnwillingToPerform.
  def on_modify_dn(dn, new_rdn, delete_old_rdn, new_superior, conn) : LDAP::Response::Code

  # Compare an attribute value. Return CompareTrue or CompareFalse.
  # Default: UnwillingToPerform.
  def on_compare(dn, attribute, value, conn) : LDAP::Response::Code

  # Called on UnbindRequest or disconnect. Default is a no-op.
  def on_unbind(conn) : Nil
end
```

#### `LDAP::Server::SearchEntry`

```crystal
record SearchEntry, dn : String, attributes : Hash(String, Array(String))
```

#### `LDAP::Server::Modification`

Passed to `on_modify` — one per change in the ModifyRequest:

```crystal
record Modification,
  operation : LDAP::ModifyOperation,  # Add, Delete, or Replace
  attribute : String,
  values : Array(String)
```

### `LDAP::Server::Filter`

Filters arrive pre-parsed from the client's BER. You can use them for in-memory matching:

```crystal
filter.matches?(dn, attributes)  # → Bool
```

Or inspect the tree:

```crystal
case filter
when LDAP::Server::Filter::Equality
  puts "#{filter.attr} = #{filter.value}"
when LDAP::Server::Filter::And
  filter.filters.each { |f| ... }
when LDAP::Server::Filter::Present
  puts "#{filter.attr} exists?"
# ... etc.
```

**Filter subclasses:** `And`, `Or`, `Not`, `Equality`, `Present`, `GreaterOrEqual`, `LessOrEqual`, `Substring`.

Parse a filter from raw BER (e.g. within a SearchRequest):

```crystal
filter = LDAP::Server::Filter.from_ber(ber_node)
```

### `LDAP::Response::Code`

Standard RFC 4511 result codes are available from the `crystal-ldap` shard:

```crystal
LDAP::Response::Code::Success
LDAP::Response::Code::InvalidCredentials
LDAP::Response::Code::InsufficientAccessRights
LDAP::Response::Code::NoSuchObject
LDAP::Response::Code::EntryAlreadyExists
LDAP::Response::Code::CompareTrue
LDAP::Response::Code::CompareFalse
# ... full list in LDAP::Response::Code enum
```

### `LDAP::Server::Connection`

Passed to every handler method. Exposes:

```crystal
conn.bound?          # Bool — whether the client authenticated
conn.bound_dn        # String — the DN used to bind
conn.remote_address  # Socket::Address? — client IP/port
conn.closed?         # Bool
```

## LDAP operations supported

| Operation     | Status |
|---------------|--------|
| Bind (simple) | ✅ |
| Search        | ✅ |
| Unbind        | ✅ |
| Abandon       | ✅ (no-op; requests are synchronous) |
| StartTLS      | ✅ (pass a `OpenSSL::SSL::Context::Server` to `LDAP::Server.new`) |
| Add           | ✅ (override `on_add`) |
| Delete        | ✅ (override `on_delete`) |
| Modify        | ✅ (override `on_modify`) |
| Modify DN     | ✅ (override `on_modify_dn`) |
| Compare       | ✅ (override `on_compare`) |

## StartTLS

Pass an `OpenSSL::SSL::Context::Server` to enable StartTLS (RFC 4511 §4.14). The connection starts as plain text; the client sends a StartTLS ExtendedRequest to upgrade:

```crystal
tls = OpenSSL::SSL::Context::Server.new
tls.certificate_chain = "/etc/ldap/server.crt"
tls.private_key       = "/etc/ldap/server.key"

server = LDAP::Server.new(MyHandler.new, tls_context: tls, port: 389)
server.listen
```

Test with ldapsearch:

```sh
ldapsearch -H ldap://localhost:389 -ZZ -x -b "dc=example,dc=com" "(uid=alice)"
# -ZZ requires StartTLS to succeed
```

## Running the specs

```sh
crystal spec
```

## Contributing

1. Fork it (<https://github.com/dirless/ldap-server.cr/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request

## License

MIT — see [LICENSE](LICENSE).
