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
    pending
    lambda {
      CyberplatPKI::Key.new_public(@pubkey, 12345)
    }.should raise_error()

    lambda {
      CyberplatPKI::Key.new_public("foo", 17033)
    }.should raise_error()
  end

  it "should load private keys" do
    lambda {
      CyberplatPKI::Key.new_private(@seckey, '1111111111')
    }.should_not raise_error
  end

  it "fails loading private key from invalid source" do
    pending
    lambda {
      CyberplatPKI::Key.new_private("foo", '1111111111')
    }.should raise_error
  end

  it "fails loading private key with invalid password" do
    pending
    lambda {
      CyberplatPKI::Key.new_private(@seckey, 'foo')
    }.should raise_error
  end

  SIGNED = <<-SIGNED.rstrip.freeze
0000027201SM000000110000001100000125
api17032            00017033
                    00000000
BEGIN
Hello world
END
BEGIN SIGNATURE
iQBRAwkBAABCiVCdLGsBAWxqAf9KzuezPsLJV6221uXNLzqG5Bc86dLCenvdgY+K
Qj3H3d0ogyGuZ4O1UvdrlLDKDdbCanYrXAHQAYOE65d2ax7GsAHH
=mQ/Y
END SIGNATURE
  SIGNED

  it "can sign a block" do
    privkey = CyberplatPKI::Key.new_private(@seckey, '1111111111')
    privkey.sign("Hello world").should == SIGNED
  end

  it "can verify a block" do
    pubkey = CyberplatPKI::Key.new_public(@pubkey, 17033)
    pubkey.verify(SIGNED).should be_true
  end

  it "fails verifying an invalid block" do
    pubkey = CyberplatPKI::Key.new_public(@pubkey, 17033)
    fail_signed = SIGNED.sub('BAABC', 'BAAAC')
    pubkey.verify(fail_signed).should be_false
  end
end