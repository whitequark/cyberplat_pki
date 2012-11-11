require "stringio"
require "base64"
require "digest/crc24"

module CyberplatPKI
  class Document
    attr_accessor :engine, :type, :subject, :ca, :body, :signature, :data_length

    def initialize
      @engine = nil
      @type = nil
      @subject = nil
      @ca = nil
      @body = nil
      @signature = nil
      @unknown1 = nil
    end

    def self.load(source)
      source = source.sub /^[ \t\n\r]*/, ''

      io = StringIO.new source, "rb"
      io.extend DocumentIORoutines

      documents = []

      until io.eof?
        begin
          documents << io.read_document
        rescue EOFError => e
          raise "CyberplatPKI: CRYPT_ERR_INVALID_FORMAT (unexpected end of document)"
        end
      end

      documents
    end

    def self.save(documents)
      io = StringIO.new '', "wb"
      io.extend DocumentIORoutines

      documents.each { |document| io.write_document document }

      io.string[0...-2] # Strip trailing CRLF of last document
    end

    def self.encode64(data)
      encoded = Base64.encode64(data).gsub /\n/, "\r\n"

      crc = Digest::CRC24.checksum data

      encoded << "=#{Base64.encode64([ crc ].pack("N")[1..-1])[0..-2]}"

      encoded
    end

    def self.decode64(data)
      lines = data.split "\r\n"

      data = ""
      crc = nil

      lines.each do |line|
        if line[0] == '='
          crc, = "\0".concat(Base64.decode64(line[1..-1])).unpack('N')
        else
          data << line
        end
      end

      data = Base64.decode64 data

      if !crc.nil?
        calculated_crc = Digest::CRC24.checksum data

        raise "CyberplatPKI: CRYPT_ERR_RADIX_DECODE (invalid data checksum)" if calculated_crc != crc
      end

      data
    end
  end
end
