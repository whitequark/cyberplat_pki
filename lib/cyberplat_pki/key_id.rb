module CyberplatPKI
  class KeyId
    attr_accessor :key_name, :key_serial

    def initialize(key_name = nil, key_serial = nil)
      @key_name = key_name
      @key_serial = key_serial
    end

    def ==(other)
      key_name == other.key_name && key_serial == other.key_serial
    end
  end
end

