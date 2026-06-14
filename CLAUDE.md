# ldap-server.cr

Crystal shard for building LDAP servers. Handles the protocol layer (BER/ASN.1 framing, message dispatch, RFC 4511 operations, response encoding) so you focus only on directory logic.

> This shard was written by Claude (Anthropic).

Built on top of `crystal-ldap` — reuses its BER primitives, tag definitions, and filter infrastructure.

## Language / stack

- Crystal
- Depends on `crystal-ldap` (dirless fork) for BER/filter primitives

## Key entry points

| File | Purpose |
|------|---------|
| `src/ldap/server/server.cr` | `LDAP::Server` — TCP server, fiber-per-client accept loop, StartTLS support |
| `src/ldap/server/connection.cr` | `LDAP::Server::Connection` — per-client state (`bound?`, `bound_dn`, `remote_address`) |
| `src/ldap/server/handler.cr` | `LDAP::Server::Handler` — abstract base; subclass and override `on_bind`, `on_search`, optional CRUD methods |
| `src/ldap/server/filter.cr` | `LDAP::Server::Filter` — pre-parsed filter tree with `matches?` for in-memory evaluation |

## Usage pattern

```crystal
class MyHandler < LDAP::Server::Handler
  def on_bind(dn, password, conn) : LDAP::Response::Code
    # return Success or InvalidCredentials
  end

  def on_search(base, scope, filter, attrs, conn, &block : SearchEntry ->) : LDAP::Response::Code
    # yield matching SearchEntry objects
  end
end

LDAP::Server.new(MyHandler.new, port: 1389).listen
```

## Supported operations

Bind, Search, Add, Delete, Modify, ModifyDN, Compare, Unbind, Abandon, StartTLS.

## Build & test

```sh
shards install
crystal spec
```

The port is bound at `Server.new` construction time (before `listen`), so tests can connect immediately after creation.
