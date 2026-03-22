require "ldap"
require "./filter"

module LDAP
  class Server
    # A single entry returned during a search.
    record SearchEntry, dn : String, attributes : Hash(String, Array(String))

    # Handler is the interface you implement to back the LDAP server with
    # your own directory logic.  Subclass it and override at minimum
    # `on_bind` and `on_search`.
    abstract class Handler
      # Called when a client sends a BindRequest (simple authentication).
      #
      # Return `LDAP::Response::Code::Success` to accept the bind, or an
      # appropriate error code (e.g. `InvalidCredentials`) to reject it.
      abstract def on_bind(dn : String, password : String, conn : Connection) : LDAP::Response::Code

      # Called when a client sends a SearchRequest.
      #
      # Yield `SearchEntry` objects for each matching entry; after the block
      # returns the server automatically sends SearchResultDone.
      # Return the final result code (usually `Success`).
      abstract def on_search(
        base : String,
        scope : LDAP::SearchScope,
        filter : LDAP::Server::Filter,
        attrs : Array(String),
        conn : Connection,
        &block : SearchEntry ->
      ) : LDAP::Response::Code

      # Called when the client sends an UnbindRequest or disconnects.
      # Override for session cleanup; the default is a no-op.
      def on_unbind(conn : Connection) : Nil
      end
    end
  end
end
