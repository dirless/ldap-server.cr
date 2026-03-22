# ldap-server.cr

A Crystal shard for building LDAP servers. Handles the protocol layer (BER/ASN.1 framing, message dispatch, response encoding) so you can focus on directory logic.

Built on top of [spider-gazelle/crystal-ldap](https://github.com/spider-gazelle/crystal-ldap), reusing its BER primitives, tag definitions, and filter infrastructure.

## Features

- TCP server with one fiber per client
- Simple, abstract `Handler` class — implement `on_bind` and `on_search`
- Full RFC 4511 filter tree parsed from BER (AND, OR, NOT, equality, substring, present, ≥, ≤) with optional in-memory `matches?`
- Supports: Bind, Search, Unbind, Abandon; returns `UnwillingToPerform` for unimplemented operations
- Works with any LDAP client (tested with [crystal-ldap](https://github.com/spider-gazelle/crystal-ldap), [ldapsearch](https://linux.die.net/man/1/ldapsearch))

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
ENTRIES = {
  "cn=alice,dc=example,dc=com" => {
    "cn"          => ["Alice"],
    "uid"         => ["alice"],
    "objectClass" => ["person"],
  },
}

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

Subclass and override:

```crystal
abstract class LDAP::Server::Handler
  # Return Success to accept the bind, or an error code to reject it.
  abstract def on_bind(dn, password, conn) : LDAP::Response::Code

  # Yield matching SearchEntry objects; return the final result code.
  abstract def on_search(base, scope, filter, attrs, conn, &block : SearchEntry ->) : LDAP::Response::Code

  # Called on UnbindRequest or disconnect. Default is a no-op.
  def on_unbind(conn) : Nil
end
```

#### `LDAP::Server::SearchEntry`

```crystal
record SearchEntry, dn : String, attributes : Hash(String, Array(String))
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

Standard RFC 4511 result codes are available from the upstream `crystal-ldap` shard:

```crystal
LDAP::Response::Code::Success
LDAP::Response::Code::InvalidCredentials
LDAP::Response::Code::InsufficientAccessRights
LDAP::Response::Code::NoSuchObject
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
| Modify        | 🔜 returns UnwillingToPerform |
| Add           | 🔜 returns UnwillingToPerform |
| Delete        | 🔜 returns UnwillingToPerform |
| Modify DN     | 🔜 returns UnwillingToPerform |
| Compare       | 🔜 returns UnwillingToPerform |
| StartTLS      | 🔜 planned |

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
