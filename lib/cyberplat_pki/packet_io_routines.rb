require "stringio"
require "openssl"

module CyberplatPKI
  module PacketIORoutines
    attr_accessor :cipher, :checksum

    def read_packet(password = nil)
      header = readbyte
      raise "CyberplatPKI: CRYPT_ERR_INVALID_PACKET_FORMAT (invalid packet header)" if (header & 0xC0) != 0x80

      case header & 3
      when 0
        data_length = readbyte

      when 1
        data_length, = read(2).unpack 'n'

      when 2
        data_length, = read(4).unpack 'N'

      else
        raise "CyberplatPKI: CRYPT_ERR_INVALID_PACKET_FORMAT (invalid packet length type: #{header % 3}"
      end

      packet_type = (header >> 2) & 0x0F

      data = read data_length
      packet_class = PACKET_TYPES[packet_type]

      raise "CyberplatPKI: CRYPT_ERR_INVALID_PACKET_FORMAT (unsupported packet type: #{packet_type})" if packet_class.nil?

      StringIO.open(data, "rb") do |io|
        io.extend PacketIORoutines
        packet_class.load io, context_for_password(password)
      end
    end

    def write_packet(packet, password = nil)
      io = StringIO.open ''.encode('BINARY'), 'wb'
      io.extend PacketIORoutines
      packet.save io, context_for_password(password)

      data = io.string

      packet_type = (PACKET_TYPES.key(packet.class) << 2) | 0x80

      if data.length <= 0xFF && !packet.kind_of?(SignaturePacket) && !packet.kind_of?(KeyPacket)
        putc packet_type
        putc data.length
      elsif data.length <= 0xFFFF
        putc packet_type | 1

        write [ data.length ].pack("n")

      else
        putc packet_type | 2

        write [ data.length ].pack("N")
      end

      write data
    end

    def read_mpi
      header = read(2)

      mpi_bits, = header.unpack("n")
      data = read((mpi_bits + 7) / 8)

      if !cipher.nil?
        cipher.resync
        data = cipher.decrypt data
      end

      add_checksum header
      add_checksum data

      OpenSSL::BN.new data, 2
    end

    def write_mpi(bn)
      header = [ bn.num_bits ].pack("n")
      data = bn.to_s 2

      add_checksum header
      add_checksum data

      write header

      if !cipher.nil?
        cipher.resync
        data = cipher.encrypt data
      end

      write data
    end

    private

    def context_for_password(password)
      if password.nil?
        nil
      else
        context = IdeaCfb.new
        context.start_encryption OpenSSL::Digest::MD5.digest(password) # yes, encryption

        context
      end
    end

    def add_checksum(string)
      if !checksum.nil?
        @checksum = (@checksum + string.sum(16)) & 0xFFFF
      end
    end
  end
end
