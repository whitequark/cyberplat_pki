require_relative 'cyberplat_pki/key_id'
require_relative 'cyberplat_pki/document'
require_relative 'cyberplat_pki/document_io_routines'
require_relative 'cyberplat_pki/packet'
require_relative 'cyberplat_pki/signature_packet'
require_relative 'cyberplat_pki/key_packet'
require_relative 'cyberplat_pki/private_key_packet'
require_relative 'cyberplat_pki/trust_packet'
require_relative 'cyberplat_pki/user_id_packet'
require_relative 'cyberplat_pki/packet_io_routines'
require_relative 'cyberplat_pki/key'
require_relative 'cyberplat_pki/idea_cfb'

module CyberplatPKI
  PACKET_TYPES = {
    2  => SignaturePacket,
    5  => PrivateKeyPacket,
    6  => KeyPacket,
    12 => TrustPacket,
    13 => UserIdPacket
  }
end

