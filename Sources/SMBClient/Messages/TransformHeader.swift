import Foundation

/// v2-236 M2: SMB2 TRANSFORM_HEADER (MS-SMB2 2.2.41). An encrypted message is
/// not an SMB2 message with an encrypted body - the 64-byte SMB2 header is
/// itself inside the ciphertext, and this 52-byte header replaces it on the
/// wire. Anything that parses a response by reading a `Header` off the front
/// therefore has to decrypt first, or it reads the tag as a command.
public struct TransformHeader {
  public static let size = 52
  /// 0xFD 'S' 'M' 'B', little-endian, against 0xFE 'S' 'M' 'B' for a plain one.
  public static let protocolId: UInt32 = 0x424D53FD

  public let signature: Data
  public let nonce: Data
  public let originalMessageSize: UInt32
  public let flags: UInt16
  public let sessionId: UInt64

  public init(signature: Data, nonce: Data, originalMessageSize: UInt32, sessionId: UInt64) {
    self.signature = signature
    self.nonce = nonce
    self.originalMessageSize = originalMessageSize
    self.flags = 0x0001            // ENCRYPTED, the only value 3.1.1 defines
    self.sessionId = sessionId
  }

  public init?(data: Data) {
    guard data.count >= TransformHeader.size else { return nil }
    let reader = ByteReader(data)
    guard (reader.read() as UInt32) == TransformHeader.protocolId else { return nil }
    signature = reader.read(count: 16)
    nonce = reader.read(count: 16)
    originalMessageSize = reader.read()
    _ = reader.read() as UInt16    // Reserved
    flags = reader.read()
    sessionId = reader.read()
  }

  public static func isEncrypted(_ data: Data) -> Bool {
    guard data.count >= 4 else { return false }
    return ByteReader(data).read() as UInt32 == protocolId
  }

  public func encoded() -> Data {
    var data = Data()
    data += TransformHeader.protocolId
    data += signature
    data += nonce
    data += originalMessageSize
    data += UInt16(0)
    data += flags
    data += sessionId
    return data
  }

  /// The associated data GCM authenticates: everything from the nonce field to
  /// the end of the header. The signature field itself is the tag, so it is
  /// outside - and so is the protocol id.
  public func associatedData() -> Data {
    Data(encoded()[20..<TransformHeader.size])
  }
}
