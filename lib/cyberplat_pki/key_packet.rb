require "openssl"

module CyberplatPKI
  class KeyPacket < Packet
    attr_accessor :serial, :timestamp, :valid_days, :algorithm, :key

    def self.load(io, context)
      version = io.readbyte

      # RFC4880 says:
      #
      # V3 keys are deprecated.  They contain three weaknesses.  First, it is
      # relatively easy to construct a V3 key that has the same Key ID as any
      # other key because the Key ID is simply the low 64 bits of the public
      # modulus.  Secondly, because the fingerprint of a V3 key hashes the
      # key material, but not its length, there is an increased opportunity
      # for fingerprint collisions.  Third, there are weaknesses in the MD5
      # hash algorithm that make developers prefer other algorithms.  See
      # below for a fuller discussion of Key IDs and fingerprints.
      #
      # Beware.

      raise "CyberplatPKI: CRYPT_ERR_INVALID_PACKET_FORMAT (unsupported key version: #{version})" if version != 0x03

      key = KeyPacket.new

      key.serial, key.timestamp, key.valid_days, algorithm = io.read(11).unpack "NNnC"

      raise "CyberplatPKI: CRYPT_ERR_INVALID_PACKET_FORMAT (unsupported algorithm #{algorithm})" if algorithm != 1

      key.key = OpenSSL::PKey::RSA.new
      key.key.n = io.read_mpi
      key.key.e = io.read_mpi

      key
    end

    def save(io, context)
      io.write [ 3, serial, timestamp, valid_days, 1 ].pack("CNNnC")

      io.write_mpi key.n
      io.write_mpi key.e
    end
  end
end
