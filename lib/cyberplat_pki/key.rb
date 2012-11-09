module CyberplatPKI
  class Key
    attr_reader :internal

    class << self
      def new_private(source, password, engine=Library::DEFAULT_ENGINE)
        internal = Library::Key.new

        Library.invoke :OpenSecretKey,
            engine,
            source, source.length,
            password,
            internal

        new(internal)
      end

      def new_public(source, serial, ca_key=nil, engine=Library::DEFAULT_ENGINE)
        internal = Library::Key.new

        if ca_key
          ca_key = ca_key.internal
        end

        Library.invoke :OpenPublicKey,
            engine,
            source, source.length,
            serial,
            internal,
            ca_key

        new(internal)
      end

      private :new
    end

    def initialize(internal)
      @internal = internal
      define_finalizer(self, lambda {
        Library.invoke :CloseKey, internal
      })
    end

    def sign(data)
      # Be fucking optimistic. Someone, please teach the morons from
      # cyberplat how to design APIs and document them.
      # I sincerely hope this does not segfault in production.
      result = FFI::MemoryPointer.new(:char, data.length + 1024)

      Library.invoke :Sign,
          data,   data.size,
          result, result.size,
          @internal

      result.read_string
    end

    def verify(data_with_signature)
      Library.invoke :Verify,
          data_with_signature, data_with_signature.size,
          nil, nil,
          @internal
    end
  end
end