require "openssl"

module CyberplatPKI
  class Key
    module Helpers
      def self.key_from_document_set(list, type, serial, password = nil)
        document = list.find do |doc|
          doc.type == type && (serial == 0 || doc.subject.key_serial == serial)
        end

        raise "CyberplatPKI: CRYPT_ERR_PUB_KEY_NOT_FOUND (key with specified serial has not been found in the document)" if document.nil?

        key = Key.new
        key.serial    = document.subject.key_serial
        key.name      = document.subject.key_name
        key.packets   = Packet.load Document.decode64(document.body), password
        key.signature = Packet.load Document.decode64(document.signature), password

        [ key, document ]
      end

      def self.find_record(list, record_class)
        record = list.find { |record| record.kind_of? record_class }

        raise "CyberplatPKI: CRYPT_ERR_INVALID_PACKET_FORMAT (#{record_class.name} not found in the document)" if record.nil?

        record
      end
    end

    attr_accessor :serial, :name, :signature, :ca_key, :packets

    def self.new_private(source, password = nil)
      documents = Document.load source

      key, document = Helpers.key_from_document_set documents, :NM, 0, password
      key.ca_key = key

      key
    end

    def self.new_public(source, serial, ca_key = nil)
      documents = Document.load source

      key, document = Helpers.key_from_document_set documents, :NS, serial
      if ca_key.nil?
        if document.subject == document.ca
          key.ca_key = key
        else
          key.ca_key, ca_document = Helpers.key_from_document_set documents, :NS, document.ca.key_serial
          key.ca_key.ca_key = key.ca_key

          key.ca_key.validate
        end
      else
        key.ca_key = ca_key
      end

      key.validate

      key
    end

    def initialize
      @serial = nil
      @name = nil
      @signature = nil
      @ca_key = nil
      @packets = nil
    end

    def sign(data)
      signature = SignaturePacket.new

      signature.metadata = [
        0x01,         # Signature type
        serial,       # Signing key serial number
        Time.now.to_i # Timestamp
      ].pack("CNN")

      key_packet = Helpers.find_record packets, KeyPacket

      digest = OpenSSL::Digest::MD5.new
      signature.signature = key_packet.key.sign digest, data + signature.metadata

      # Re-hash to get 'first word of digest'
      digest.reset
      digest.update data
      digest.update signature.metadata
      signature.hash_msw = digest.digest[0..1]

      trust = TrustPacket.new
      trust.trust = 0xC7.chr

      signature_block = Packet.save([ signature, trust ])

      doc = Document.new
      doc.engine      = 1
      doc.type        = :SM
      doc.subject     = KeyId.new @name, @serial
      doc.ca          = KeyId.new '', 0
      doc.data_length = data.length
      doc.body        = data
      doc.signature   = Document.encode64 signature_block

      text = Document.save [ doc ]

      text
    end

    def verify(data_with_signature)
      documents = Document.load data_with_signature

      raise "CyberplatPKI: CRYPT_ERR_INVALID_FORMAT (expected one document of type SM)" if documents.length != 1 || documents[0].type != :SM

      document, = *documents

      signature_packet, = Packet.load Document.decode64(document.signature)
      key_packet        = Helpers.find_record packets, KeyPacket

      digest = OpenSSL::Digest::MD5.new
      signature = signature_packet.signature.ljust key_packet.key.n.num_bytes, 0.chr
      key_packet.key.verify digest, signature, document.body + signature_packet.metadata
    end

    def validate
      signature_packet = Helpers.find_record signature,      SignaturePacket
      key_packet       = Helpers.find_record packets,        KeyPacket
      user_id_packet   = Helpers.find_record packets,        UserIdPacket
      ca_key_packet    = Helpers.find_record ca_key.packets, KeyPacket

      io = StringIO.open ''.encode('BINARY'), 'wb'
      io.extend PacketIORoutines

      io.seek 3
      key_packet.save io, nil

      data_length = io.pos - 3
      io.rewind
      io.write [ 0x99, data_length ].pack "Cn"
      io.seek 0, IO::SEEK_END

      io.write user_id_packet.user_id
      io.write signature_packet.metadata

      digest = OpenSSL::Digest::MD5.new
      signature = signature_packet.signature.rjust ca_key_packet.key.n.num_bytes, 0.chr
      valid = ca_key_packet.key.verify digest, signature, io.string

      raise "CyberplatPKI: CRYPT_ERR_INVALID_KEY (key signature verification failed)" unless valid
    end
  end
end
