require 'spec_helper'

describe CyberplatPKI::Key do
  before do
    @pubkey = File.read(File.expand_path('../keys/pubkeys.key', __FILE__))
    @seckey = File.read(File.expand_path('../keys/secret.key', __FILE__))
  end

  it "should load public keys" do
    lambda {
      CyberplatPKI::Key.new_public(@pubkey, 17033)
    }.should_not raise_error
  end

  it "fails loading public key from invalid source" do
    lambda {
      CyberplatPKI::Key.new_public(@pubkey, 12345)
    }.should raise_error(/PUB_KEY_NOT_FOUND/)

    lambda {
      CyberplatPKI::Key.new_public("foo", 17033)
    }.should raise_error(/INVALID_FORMAT/)
  end

  it "should load private keys" do
    lambda {
      CyberplatPKI::Key.new_private(@seckey, '1111111111')
    }.should_not raise_error
  end

  it "fails loading private key from invalid source" do
    lambda {
      CyberplatPKI::Key.new_private("foo", '1111111111')
    }.should raise_error(/INVALID_FORMAT/)
  end

  it "fails loading private key with invalid password" do
    lambda {
      CyberplatPKI::Key.new_private(@seckey, 'foo')
    }.should raise_error(/INVALID_PASSWD/)
  end

  SIGNED = <<-SIGNED.gsub("\n", "\r\n").freeze
0000027201SM000000110000001100000125
api17032            00017033
                    00000000
BEGIN
Hello world
END
BEGIN SIGNATURE
iQBRAwkBAABCiVCdMQoBAcf2AfwOYzgQxyj1jwRv/6JdjCFh+lguLENscUFfaNXu
OIi4jaGbW8jFrxnUj5AaoeA/WJtFuBayNdBmyiQpeisngU6XsAHH
=z1vE
END SIGNATURE
  SIGNED

  HELLO_WORLD = <<-HELLO_WORLD
z/Do4uXyLCDs6PAhCg==
HELLO_WORLD

  it "can sign and then verify block" do
    privkey = CyberplatPKI::Key.new_private(@seckey, '1111111111')
    pubkey = CyberplatPKI::Key.new_public(@pubkey, 17033)

    signed = privkey.sign("Hello world")
    pubkey.verify(signed).should be_true
  end

  it "can verify a block" do
    pubkey = CyberplatPKI::Key.new_public(@pubkey, 17033)

    pubkey.verify(SIGNED).should be_true
  end

  it "fails verifying an invalid block" do
    pubkey = CyberplatPKI::Key.new_public(@pubkey, 17033)

    fail_signed = SIGNED.sub('world', 'wor1d')
    pubkey.verify(fail_signed).should be_false
  end

  it "properly handles Windows-1251 strings" do
    privkey = CyberplatPKI::Key.new_private(@seckey, '1111111111')

    signed = privkey.sign Base64.decode64(HELLO_WORLD).force_encoding('Windows-1251')

    signed.encoding.names.include?("Windows-1251").should be_true
  end
end