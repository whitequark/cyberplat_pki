require 'ffi'

module CyberplatPKI::Library
  extend FFI::Library

  if defined?(Rubinius) # Fuck you.
    if Rubinius.windows?
      tuple = "windows-"
    elsif RUBY_PLATFORM =~ /linux/
      tuple = "linux-"
    else
      tuple = "unknown-"
    end

    if FFI::Platform::ARCH =~ /x86_64/
      tuple << "x86_64"
    elsif FFI::Platform::ARCH =~ /(i.?|x)86/
      tuple << "i386"
    end
  else
    tuple = "#{FFI::Platform::OS}-#{FFI::Platform::ARCH}"
  end

  if tuple == 'windows-i386'
    ffi_lib File.expand_path('../../../ext/libipriv32.dll', __FILE__)
  elsif tuple == 'linux-i386'
    ffi_lib File.expand_path('../../../ext/libipriv-linux32.so', __FILE__)
  else
    raise "CyberplatPKI: unsupported platform #{tuple}."
  end

  Errors = {
    -1   => "BAD_ARGS",
    -2   => "OUT_OF_MEMORY",
    -3   => "INVALID_FORMAT",
    -4   => "NO_DATA_FOUND",
    -5   => "INVALID_PACKET_FORMAT",
    -6   => "UNKNOWN_ALG",
    -7   => "INVALID_KEYLEN",
    -8   => "INVALID_PASSWD",
    -9   => "DOCTYPE",
    -10  => "RADIX_DECODE",
    -11  => "RADIX_ENCODE",
    -12  => "INVALID_ENG",
    -13  => "ENG_NOT_READY",
    -14  => "NOT_SUPPORT",
    -15  => "FILE_NOT_FOUND",
    -16  => "CANT_READ_FILE",
    -17  => "INVALID_KEY",
    -18  => "SEC_ENC",
    -19  => "PUB_KEY_NOT_FOUND",
    -20  => "VERIFY",
    -21  => "CREATE_FILE",
    -22  => "CANT_WRITE_FILE",
    -23  => "INVALID_KEYCARD",
    -24  => "GENKEY",
    -25  => "PUB_ENC",
    -26  => "SEC_DEC",
  }

  ENGINE_RSAREF   = 0
  ENGINE_OPENSSL  = 1
  ENGINE_PKCS11   = 2
  ENGINE_WINCRYPT = 3

  DEFAULT_ENGINE  = ENGINE_RSAREF

  ENGCMD_IS_READY              = 0
  ENGCMD_GET_ERROR             = 1
  ENGCMD_SET_PIN               = 2
  ENGCMD_SET_PKCS11_LIB        = 3
  ENGCMD_GET_PKCS11_SLOTS_NUM  = 4
  ENGCMD_GET_PKCS11_SLOT_NAME  = 5
  ENGCMD_SET_PKCS11_SLOT       = 6
  ENGCMD_ENUM_PKCS11_KEYS      = 7
  ENGCMD_ENUM_PKCS11_PUBKEYS   = 8

  KEY_TYPE_RSA_SECRET  = 1
  KEY_TYPE_RSA_PUBLIC  = 2

  MAX_USERID_LENGTH    = 20

  class Key < FFI::Struct
    layout :eng,       :short,
           :type,      :short,
           :keyserial, :ulong,
           :userid,    [:char, 24],
           :key,       :pointer
  end

  # Only required functions are defined.
  # For all functions, zero return code is success, nonzero is error.

  # int Crypt_Initialize(void)
  attach_function :Crypt_Initialize, [], :int

  # int Crypt_OpenSecretKey(int eng, const char* src, int src_len, const char* password, IPRIV_KEY* key)
  attach_function :Crypt_OpenSecretKey, [:int, :string, :int, :string, :pointer], :int

  # int Crypt_OpenPublicKey(int eng, const char* src, int src_len, int keyserial, IPRIV_KEY* key, IPRIV_KEY* cakey)
  attach_function :Crypt_OpenPublicKey, [:int, :string, :int, :int, :pointer, :pointer], :int

  # int Crypt_Sign(const char* src, int src_len, char* dst, int dst_len, IPRIV_KEY* key);
  attach_function :Crypt_Sign, [:string, :int, :pointer, :int, :pointer], :int

  # int Crypt_Verify(const char* src, int src_len, const char** pdst, int* pndst,IPRIV_KEY* key);
  attach_function :Crypt_Verify, [:string, :int, :pointer, :pointer, :pointer], :int

  # int Crypt_CloseKey(IPRIV_KEY* key)
  attach_function :Crypt_CloseKey, [:pointer], :int

  # int Crypt_Done(void)
  attach_function :Crypt_Done, [], :int

  def self.handle_error(function, retval)
    if retval < 0
      error = Errors[retval] || "UNKNOWN"
      raise "CyberplatPKI: Cannot invoke #{function}: #{error} (#{retval})"
    end

    retval
  end

  def self.invoke(function, *args)
    function = :"Crypt_#{function}"
    handle_error(function, send(function, *args))
  end
end