module CyberplatPKI
  class TrustPacket < Packet
    attr_accessor :trust

    def initialize(trust = nil)
      @trust = trust
    end

    def self.load(io, context)
      new io.read
    end

    def save(io, context)
      io.write @trust
    end
  end
end
