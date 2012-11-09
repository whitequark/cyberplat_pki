module CyberplatPKI
  require_relative 'cyberplat_pki/library'
  require_relative 'cyberplat_pki/key'

  Library.invoke :Initialize

  at_exit {
    Library.invoke :Done
  }
end
