require "socket"
require "log"
require "./handler"
require "./connection"

module LDAP
  # Server listens for LDAP clients and dispatches to a Handler implementation.
  #
  # Example:
  #
  #   class MyHandler < LDAP::Server::Handler
  #     def on_bind(dn, password, conn)
  #       password == "secret" ? LDAP::Response::Code::Success
  #                            : LDAP::Response::Code::InvalidCredentials
  #     end
  #
  #     def on_search(base, scope, filter, attrs, conn, &block)
  #       block.call SearchEntry.new("cn=alice,dc=example,dc=com", {"cn" => ["alice"]})
  #       LDAP::Response::Code::Success
  #     end
  #   end
  #
  #   server = LDAP::Server.new(MyHandler.new, port: 1389)
  #   server.listen
  #
  class Server
    Log = ::Log.for("ldap.server")

    getter port : Int32
    getter host : String

    def initialize(@handler : Handler, @host : String = "0.0.0.0", @port : Int32 = 389)
      @server = TCPServer.new(@host, @port)
    end

    # Accept connections in a loop; each client is handled in its own fiber.
    # Blocks the calling fiber until `close` is called.
    def listen : Nil
      Log.info { "LDAP server listening on #{@host}:#{@port}" }
      loop do
        client = @server.accept? || break
        spawn handle_client(client)
      end
    end

    # Stop accepting new connections.
    def close : Nil
      @server.close
    end

    private def handle_client(socket : TCPSocket) : Nil
      remote = socket.remote_address rescue nil
      Log.debug { "client connected: #{remote}" }
      conn = Connection.new(socket, @handler, remote)
      conn.run
      Log.debug { "client disconnected: #{remote}" }
    rescue e
      Log.error(exception: e) { "error handling client #{socket.remote_address rescue "?"}" }
    end
  end
end
