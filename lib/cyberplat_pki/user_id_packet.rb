module CyberplatPKI
  class UserIdPacket < Packet
    attr_accessor :user_id

    def initialize(user_id = nil)
      @user_id = user_id
    end

    def self.load(io, context)
      new io.read
    end

    def save(io, context)
      io.write @user_id
    end
  end
end
