require "ldap"

module LDAP
  class Server
    # Filter represents a parsed LDAP search filter received from a client.
    # Use Filter.from_ber to parse the BER-encoded filter out of a SearchRequest.
    # Use filter.matches?(dn, attributes) for in-memory filtering.
    abstract class Filter
      # Parse a BER-encoded LDAP filter (RFC 4511 §4.5.1.7).
      # The BER node is expected to have TagClass::ContextSpecific.
      def self.from_ber(ber : LDAP::BER) : Filter
        case ber.tag_number
        when 0 # and
          And.new(ber.children.map { |c| from_ber(c) })
        when 1 # or
          Or.new(ber.children.map { |c| from_ber(c) })
        when 2 # not
          Not.new(from_ber(ber.children.first))
        when 3 # equalityMatch (AttributeValueAssertion)
          ch = ber.children
          Equality.new(ch[0].get_string, ch[1].get_string)
        when 4 # substrings
          parse_substring(ber)
        when 5 # greaterOrEqual
          ch = ber.children
          GreaterOrEqual.new(ch[0].get_string, ch[1].get_string)
        when 6 # lessOrEqual
          ch = ber.children
          LessOrEqual.new(ch[0].get_string, ch[1].get_string)
        when 7 # present — Context-specific [7], value is the attribute name bytes
          Present.new(String.new(ber.get_bytes))
        when 8 # approxMatch
          ch = ber.children
          Equality.new(ch[0].get_string, ch[1].get_string)
        else
          Present.new("objectClass") # safe fallback for unknown filter types
        end
      end

      # Returns true if this filter matches the given entry.
      # Attribute comparisons are case-insensitive on both name and value.
      abstract def matches?(dn : String, attrs : Hash(String, Array(String))) : Bool

      # Logical AND — all sub-filters must match.
      class And < Filter
        getter filters : Array(Filter)

        def initialize(@filters); end

        def matches?(dn : String, attrs : Hash(String, Array(String))) : Bool
          @filters.all?(&.matches?(dn, attrs))
        end
      end

      # Logical OR — at least one sub-filter must match.
      class Or < Filter
        getter filters : Array(Filter)

        def initialize(@filters); end

        def matches?(dn : String, attrs : Hash(String, Array(String))) : Bool
          @filters.any?(&.matches?(dn, attrs))
        end
      end

      # Logical NOT — inverts the sub-filter.
      class Not < Filter
        getter filter : Filter

        def initialize(@filter); end

        def matches?(dn : String, attrs : Hash(String, Array(String))) : Bool
          !@filter.matches?(dn, attrs)
        end
      end

      # Equality match — attr=value (case-insensitive).
      class Equality < Filter
        getter attr : String
        getter value : String

        def initialize(@attr, @value); end

        def matches?(dn : String, attrs : Hash(String, Array(String))) : Bool
          if @attr.downcase.in?("dn", "entrydn")
            return dn.downcase == @value.downcase
          end
          attr_values(attrs, @attr).any? { |v| v.downcase == @value.downcase }
        end
      end

      # Present — checks whether the attribute exists.
      class Present < Filter
        getter attr : String

        def initialize(@attr); end

        def matches?(dn : String, attrs : Hash(String, Array(String))) : Bool
          return true if @attr.downcase.in?("objectclass", "dn", "entrydn")
          attr_values(attrs, @attr).any?
        end
      end

      # Greater-or-equal comparison (lexicographic).
      class GreaterOrEqual < Filter
        getter attr : String
        getter value : String

        def initialize(@attr, @value); end

        def matches?(dn : String, attrs : Hash(String, Array(String))) : Bool
          attr_values(attrs, @attr).any? { |v| v >= @value }
        end
      end

      # Less-or-equal comparison (lexicographic).
      class LessOrEqual < Filter
        getter attr : String
        getter value : String

        def initialize(@attr, @value); end

        def matches?(dn : String, attrs : Hash(String, Array(String))) : Bool
          attr_values(attrs, @attr).any? { |v| v <= @value }
        end
      end

      # Substring match — initial*, *any*, *final (case-insensitive).
      class Substring < Filter
        getter attr : String
        getter initial : String?
        getter any : Array(String)
        getter final : String?

        def initialize(@attr, @initial, @any, @final); end

        def matches?(dn : String, attrs : Hash(String, Array(String))) : Bool
          attr_values(attrs, @attr).any? do |raw|
            v = raw.downcase
            ok = true
            if init = @initial
              ok = v.starts_with?(init.downcase)
            end
            if ok && (fin = @final)
              ok = v.ends_with?(fin.downcase)
            end
            ok && @any.all? { |a| v.includes?(a.downcase) }
          end
        end
      end

      private def self.parse_substring(ber : LDAP::BER) : Filter
        ch = ber.children
        # attribute name is a Universal OctetString
        attr = ch[0].get_string
        initial = nil
        final = nil
        any = [] of String
        # substring parts are Context-specific [0]=initial [1]=any [2]=final
        ch[1].children.each do |part|
          case part.tag_number
          when 0 then initial = String.new(part.get_bytes)
          when 1 then any << String.new(part.get_bytes)
          when 2 then final = String.new(part.get_bytes)
          end
        end
        Substring.new(attr, initial, any, final)
      end

      # Lookup helper — resolves attribute values case-insensitively.
      private def attr_values(attrs : Hash(String, Array(String)), name : String) : Array(String)
        attrs[name]? || attrs[name.downcase]? || attrs[name.upcase]? || [] of String
      end
    end
  end
end
