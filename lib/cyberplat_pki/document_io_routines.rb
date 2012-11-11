module CyberplatPKI
  module DocumentIORoutines
    def readline_crlf
      line = readline "\r\n"

      line.sub! /\r\n$/, ''

      line
    end

    def read_key_id
      line = readline_crlf

      raise "CyberplatPKI: CRYPT_ERR_INVALID_FORMAT (invalid key ID line: '#{line}'. Expecting 28 characters, got #{line.length})" unless line.length == 28

      KeyId.new line[0...20].rstrip!, cut_int(line, 20...28)
    end

    def write_key_id(key_id)
      printf "%-20s%08d\r\n", key_id.key_name, key_id.key_serial
    end

    def read_block(header, trailer, data_size)
      line = readline_crlf
      raise "CyberplatPKI: CRYPT_ERR_INVALID_FORMAT (unexpected header '#{line}', expecting '#{header}')" if line != header

      data_start = pos
      seek data_size, IO::SEEK_CUR

      line = readline_crlf
      raise "CyberplatPKI: CRYPT_ERR_INVALID_FORMAT (unexpected trailer '#{line}', expecting '')" if line != ''

      line = readline_crlf
      raise "CyberplatPKI: CRYPT_ERR_INVALID_FORMAT (unexpected trailer '#{line}', expecting '#{trailer}')" if line != trailer

      block_end = tell

      seek data_start
      data = read data_size
      seek block_end

      data
    end

    def write_block(header, trailer, data)
      write "#{header}\r\n#{data}\r\n#{trailer}\r\n"
    end

    def read_document
      document_start = pos

      header = readline_crlf

      raise "CyberplatPKI: CRYPT_ERR_INVALID_FORMAT (invalid document header: '#{header}'. Expecting 36 characters, got #{header.length})" unless header.length == 36

      doc = Document.new

      length            = cut_int header, 0...8      # Length of following data (e.g. document length - 8)
      doc.engine        = cut_int header, 8...10     # Engine ID
      doc.type          = header[10...12].to_sym     # Document type
      body_block        = cut_int header, 12...20    # Body block size
      doc.data_length   = cut_int header, 20...28    # Length of body in signatures
      signature_block   = cut_int header, 28...36    # Signature block size

      doc.subject       = read_key_id
      doc.ca            = read_key_id

      doc.body           = read_block 'BEGIN', 'END', body_block
      doc.signature      = read_block 'BEGIN SIGNATURE', 'END SIGNATURE', signature_block

      seek document_start + 8 + length + 2

      doc
    end

    def write_document(doc)
      start_pos = pos

      printf "XXXXXXXX%02d%s%08d%08d%08d\r\n", doc.engine, doc.type.to_s, doc.body.length, doc.data_length, doc.signature.length
      write_key_id doc.subject
      write_key_id doc.ca

      write_block 'BEGIN', 'END', doc.body
      write_block 'BEGIN SIGNATURE', 'END SIGNATURE', doc.signature

      end_pos = pos
      seek start_pos
      printf "%08d", end_pos - start_pos - 10
      seek end_pos
    end

    private

    def cut_int(string, range)
      slice = string[range]

      begin
        Integer slice, 10
      rescue ArgumentError => e
        raise "CyberplatPKI: CRYPT_ERR_INVALID_FORMAT (invalid integer in document: '#{slice}')"
      end
    end
  end
end
