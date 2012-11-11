module CyberplatPKI
  class PrivateKeyPacket < KeyPacket
    def self.load(io, context)
      key = super

      cipher = io.readbyte
      raise "CyberplatPKI: CRYPT_ERR_INVALID_PACKET_FORMAT (unsupported private key cipher: #{cipher})" if cipher != 1 # IDEA-CFB + MD5

      iv = io.read 8
      context.decrypt iv

      public_key = key.key
      key.key = OpenSSL::PKey::RSA.new

      io.cipher = context
      io.checksum = 0

      key.key.d = io.read_mpi
      key.key.p = io.read_mpi
      key.key.q = io.read_mpi
      dummy     = io.read_mpi

      calculated_checksum = io.checksum

      io.checksum = nil
      io.cipher = nil

      checksum, = io.read(2).unpack("n")
      raise "CyberplatPKI: CRYPT_ERR_INVALID_PASSWD (invalid MPI checksum. Expected #{checksum.to_s 16}, calculated #{calculated_checksum.to_s 16})" if checksum != calculated_checksum

      key.key.dmp1 = key.key.d % (key.key.p - 1)
      key.key.dmq1 = key.key.d % (key.key.q - 1)
      key.key.iqmp = key.key.q.mod_inverse key.key.p

      # jruby-openssl requires public key parameters to be set LAST
      key.key.n = public_key.n
      key.key.e = public_key.e

      key
    end

    def save(io, context)
      super

      raise NotImplementedError, "CyberplatPKI: PrivateKeyPacket#save is not implemented"
    end

  end
end
