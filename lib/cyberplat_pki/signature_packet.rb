module CyberplatPKI
  class SignaturePacket < Packet
    attr_accessor :metadata, :signature, :hash_msw

    def initialize
      @metadata = nil
      @signature = nil
      @hash_msw = nil
    end

    def self.load(io, context)
      version = io.readbyte
      raise "CyberplatPKI: CRYPT_ERR_INVALID_PACKET_FORMAT (unsupported signature length: #{version})" if version != 3

      metadata_length = io.readbyte
      raise "CyberplatPKI: CRYPT_ERR_INVALID_PACKET_FORMAT (invalid metadata length: #{metadata_length})" if metadata_length > 32

      signature = new

      signature.metadata = io.read metadata_length

      key_algorithm, hash_algorithm = io.read(2).unpack("CC")
      raise "CyberplatPKI: CRYPT_ERR_INVALID_PACKET_FORMAT (invalid public key algorithm: #{key_algorithm})" if key_algorithm != 0x01
      raise "CyberplatPKI: CRYPT_ERR_INVALID_PACKET_FORMAT (invalid hash key algorithm: #{key_algorithm})" if hash_algorithm != 0x01

      signature.hash_msw = io.read(2)
      signature_bits, = io.read(2).unpack("n")
      signature.signature = io.read (signature_bits + 7) / 8

      signature
    end

    def save(io, context)
      io.write [ 3, metadata.length ].pack "CC"
      io.write metadata
      io.write [ 1, 1 ].pack "CC"
      io.write hash_msw

      bn = OpenSSL::BN.new signature, 2
      io.write_mpi bn
    end
  end
end
