require "crypt/idea"

module CyberplatPKI
  class IdeaCfb
    BLOCK_SIZE = 8

    def initialize
      @encbuf = "\0" * BLOCK_SIZE
      @fr     = "\0" * BLOCK_SIZE
      @fre    = "\0" * BLOCK_SIZE
      @pos    = 0
      @keys   = nil
    end

    def start_encryption(key)
      @idea = Crypt::IDEA.new key.unpack('n*'), Crypt::IDEA::ENCRYPT
    end

    def start_decryption(key)
      @idea = Crypt::IDEA.new key.unpack('n*'), Crypt::IDEA::DECRYPT
    end

    def encrypt(data)
      cfb_engine data, method(:mix_enc), @idea.method(:encrypt_block)
    end


    def decrypt(data)
      cfb_engine data, method(:mix_dec), @idea.method(:decrypt_block)
    end

    def resync
      if @pos != 0
        @fr[0...BLOCK_SIZE - @pos]          = @encbuf[@pos...BLOCK_SIZE]
        @fr[BLOCK_SIZE - @pos...BLOCK_SIZE] = @encbuf[0...@pos]

        @encbuf = "\0" * BLOCK_SIZE
        @pos = 0
      end
    end

    private

    def idea_block(data)
      data
    end

    def mix_enc(data)
      outbuf = "\0" * data.length

      (@pos...@pos + data.length).each_with_index do |i, index|
        outbuf[index] = @encbuf[i] = (@fre[i].ord ^ data[index].ord).chr
      end

      @pos += data.length

      outbuf
    end

    def mix_dec(data)
      outbuf = "\0" * data.length

      (@pos...@pos + data.length).each_with_index do |i, index|
        @encbuf[i] = data[index]
        outbuf[index] = (@fre[i].ord ^ @encbuf[i].ord).chr
      end

      @pos += data.length

      outbuf
    end

    def cfb_engine(data, mix, crypt_block)
      pos = 0
      dst = ""

      while pos < data.length && @pos > 0
        n = [ BLOCK_SIZE - @pos, data.length - pos ].min

        dst << mix.call(data[pos...pos + n])
        pos += n

        if @pos == BLOCK_SIZE
          @fr = @encbuf
          @encbuf = "\0" * BLOCK_SIZE
          @pos = 0
        end
      end

      while pos < data.length
        @fre = crypt_block.call @fr

        n = [ BLOCK_SIZE, data.length - pos ].min

        dst << mix.call(data[pos...pos + n])
        pos += n

        if @pos == BLOCK_SIZE
          @fr = @encbuf
          @encbuf = "\0" * BLOCK_SIZE
          @pos = 0
        end
      end

      dst
    end
  end
end
