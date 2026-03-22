require "ldap"
require "openssl"
require "./filter"
require "./handler"

module LDAP
  class Server
    # Connection handles a single connected LDAP client.
    # It reads BER-encoded LDAP messages from the socket, dispatches them to
    # the Handler, and writes back BER-encoded responses.
    class Connection
      Log = ::Log.for("ldap.server.connection")

      getter remote_address : Socket::Address?

      # Whether the client has successfully authenticated.
      property bound : Bool = false

      # The DN the client bound as (empty string for anonymous).
      property bound_dn : String = ""

      START_TLS_OID = "1.3.6.1.4.1.1466.20037"

      def initialize(
        @socket : IO,
        @handler : Handler,
        @remote_address : Socket::Address? = nil,
        @tls_context : OpenSSL::SSL::Context::Server? = nil
      )
      end

      def closed? : Bool
        @socket.closed?
      end

      # Read and handle LDAP messages in a loop until the socket closes.
      def run : Nil
        while !@socket.closed?
          packet = @socket.read_bytes(LDAP::BER)
          handle(packet)
        end
      rescue IO::Error
        # client disconnected cleanly
      rescue e : LDAP::Error
        Log.warn { "LDAP protocol error from #{@remote_address}: #{e.message}" }
      rescue e
        Log.error(exception: e) { "unexpected error from #{@remote_address}" }
      ensure
        @socket.close unless @socket.closed?
        @handler.on_unbind(self)
      end

      private def handle(packet : LDAP::BER) : Nil
        unless packet.sequence?
          raise LDAP::Error.new("expected outer Sequence, got tag #{packet.tag_number}")
        end

        children = packet.children
        raise LDAP::Error.new("LDAPMessage must have ≥ 2 children, got #{children.size}") unless children.size >= 2

        msg_id = children[0].get_integer.to_i32
        op = children[1]

        tag = LDAP::Tag.from_value?(op.tag_number)
        unless tag
          Log.warn { "unknown operation tag #{op.tag_number} from #{@remote_address}" }
          return
        end

        case tag
        when LDAP::Tag::BindRequest
          handle_bind(msg_id, op)
        when LDAP::Tag::SearchRequest
          handle_search(msg_id, op)
        when LDAP::Tag::UnbindRequest
          @socket.close
        when LDAP::Tag::AbandonRequest
          # nothing to do — we process requests synchronously
        when LDAP::Tag::ExtendedRequest
          handle_extended(msg_id, op)
        else
          response_tag = request_to_response_tag(tag)
          send_result(msg_id, response_tag, LDAP::Response::Code::UnwillingToPerform,
            error_message: "operation not supported")
        end
      end

      # ── Bind ────────────────────────────────────────────────────────────────

      private def handle_bind(msg_id : Int32, op : LDAP::BER) : Nil
        ch = op.children
        # BindRequest: { version (Integer), name (OctetString), auth (Choice) }
        dn = ch.size >= 2 ? ch[1].get_string : ""
        # password is Context-specific [0] (simple auth), not a Universal OctetString
        password = ch.size >= 3 ? String.new(ch[2].get_bytes) : ""

        code = @handler.on_bind(dn, password, self)

        if code.success?
          @bound = true
          @bound_dn = dn
        end

        send_result(msg_id, LDAP::Tag::BindResult, code)
      end

      # ── Search ──────────────────────────────────────────────────────────────

      private def handle_search(msg_id : Int32, op : LDAP::BER) : Nil
        ch = op.children
        raise LDAP::Error.new("SearchRequest needs 8 fields, got #{ch.size}") unless ch.size >= 8

        base   = ch[0].get_string
        scope  = LDAP::SearchScope.from_value(ch[1].get_integer.to_i32)
        # ch[2] derefAliases — we pass through; ch[3] sizeLimit; ch[4] timeLimit
        # ch[5] typesOnly — ignored for now
        filter = LDAP::Server::Filter.from_ber(ch[6])
        attrs  = ch[7].children.map(&.get_string)

        code = @handler.on_search(base, scope, filter, attrs, self) do |entry|
          send_search_entry(msg_id, entry.dn, entry.attributes, attrs)
        end

        send_result(msg_id, LDAP::Tag::SearchResult, code)
      end

      # ── Extended operations ──────────────────────────────────────────────────

      private def handle_extended(msg_id : Int32, op : LDAP::BER) : Nil
        # requestName is Context-specific [0]; value is the OID bytes
        oid = op.children.first?.try { |c| String.new(c.get_bytes) } || ""

        case oid
        when START_TLS_OID
          tls = @tls_context
          unless tls
            send_result(msg_id, LDAP::Tag::ExtendedResponse,
              LDAP::Response::Code::UnwillingToPerform,
              error_message: "StartTLS not configured on this server")
            return
          end

          # Respond with success before upgrading the socket
          send_result(msg_id, LDAP::Tag::ExtendedResponse, LDAP::Response::Code::Success)

          # Wrap the plain socket in TLS; handshake happens here
          @socket = OpenSSL::SSL::Socket::Server.new(@socket, tls, sync_close: true)
        else
          send_result(msg_id, LDAP::Tag::ExtendedResponse,
            LDAP::Response::Code::ProtocolError,
            error_message: "unsupported extended operation: #{oid}")
        end
      end

      # ── Response builders ───────────────────────────────────────────────────

      private def send_result(
        msg_id : Int32,
        tag : LDAP::Tag,
        code : LDAP::Response::Code,
        matched_dn : String = "",
        error_message : String = ""
      ) : Nil
        result = LDAP.app_sequence({
          LDAP::BER.new.set_integer(code.value, LDAP::UniversalTags::Enumerated),
          LDAP::BER.new.set_string(matched_dn, LDAP::UniversalTags::OctetString),
          LDAP::BER.new.set_string(error_message, LDAP::UniversalTags::OctetString),
        }, tag)

        write_message(msg_id, result)
      end

      private def send_search_entry(
        msg_id : Int32,
        dn : String,
        all_attrs : Hash(String, Array(String)),
        requested_attrs : Array(String)
      ) : Nil
        # Empty or "*" means return all attributes.
        attrs_to_send = if requested_attrs.empty? || requested_attrs.includes?("*")
          all_attrs
        else
          all_attrs.select { |k, _| requested_attrs.any? { |r| r.downcase == k.downcase } }
        end

        attr_list = attrs_to_send.map do |name, values|
          value_set = LDAP.set(
            values.map { |v| LDAP::BER.new.set_string(v, LDAP::UniversalTags::OctetString) }
          )
          LDAP.sequence({
            LDAP::BER.new.set_string(name, LDAP::UniversalTags::OctetString),
            value_set,
          })
        end

        entry = LDAP.app_sequence({
          LDAP::BER.new.set_string(dn, LDAP::UniversalTags::OctetString),
          LDAP.sequence(attr_list),
        }, LDAP::Tag::SearchReturnedData)

        write_message(msg_id, entry)
      end

      private def write_message(msg_id : Int32, payload : LDAP::BER) : Nil
        msg = LDAP.sequence({
          LDAP::BER.new.set_integer(msg_id),
          payload,
        })
        @socket.write_bytes msg
        @socket.flush
      end

      # Map operation request tags to their corresponding response tags.
      private def request_to_response_tag(tag : LDAP::Tag) : LDAP::Tag
        case tag
        when LDAP::Tag::ModifyRequest    then LDAP::Tag::ModifyResponse
        when LDAP::Tag::AddRequest       then LDAP::Tag::AddResponse
        when LDAP::Tag::DeleteRequest    then LDAP::Tag::DeleteResponse
        when LDAP::Tag::ModifyRDNRequest then LDAP::Tag::ModifyRDNResponse
        when LDAP::Tag::CompareRequest   then LDAP::Tag::CompareResponse
        else                                  LDAP::Tag::ExtendedResponse
        end
      end
    end
  end
end
