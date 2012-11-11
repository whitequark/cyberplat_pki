require "stringio"

module CyberplatPKI
  class Packet
    def self.load(source, password = nil)
      io = StringIO.new source, "rb"
      io.extend PacketIORoutines

      packets = []

      until io.eof?
        begin
          packets << io.read_packet(password)
        rescue EOFError => e
          raise "CyberplatPKI: CRYPT_ERR_INVALID_PACKET_FORMAT (unexpected end of packet)"
        end
      end

      packets
    end

    def self.save(packets, password = nil)
      io = StringIO.new '', "wb"
      io.extend PacketIORoutines

      packets.each { |packet| io.write_packet packet, password }

      io.string
    end
  end
end
