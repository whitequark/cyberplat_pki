# CyberplatPKI

CyberplatPKI 1.0 is an FFI binding for signing Cyberplat requests. It includes both Linux and Windows versions of Cyberplat-provided library as well as the necessary wrapping code. Note that this version only works on 32-bit Linux and Windows.

CyberplatPKI 2.0 is a pure-Ruby reimplementation of the reverse-engineered signing algorithm. It should be completely compatible with the vendor-provided library. This version works everywhere.

Select the variant you'd like to install with the version specification. `gem 'cyberplat_pki', '~> 1.0'` requests the FFI version, and `gem 'cyberplat_pki', '~> 2.0'` requests the pure-Ruby one.

## Installation

Add this line to your application's Gemfile:

    gem 'cyberplat_pki'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install cyberplat_pki

## Usage

To sign:

``` ruby
privkey_serialized = File.read("private.key")
privkey = CyberplatPKI::Key.new_private(privkey_serialized, 'passphrase')

signed_data = privkey.sign(data)
```

To verify:

``` ruby
pubkey_serialized = File.read("public.key")
pubkey = CyberplatPKI::Key.new_public(pubkey_serialized, 12345) # serial = 12345

pubkey.verify(signed_data) # => true
```

Note that the library uses Windows line endings (`\r\n`) internally. You must not touch those, or the library will fail. Treat the signed data as binary, or make sure to restore the expected line endings.

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request
