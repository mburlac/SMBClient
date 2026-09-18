import Foundation

/// v2-236 M2: negotiate contexts (MS-SMB2 2.2.3.1 / 2.2.4.1). 3.1.1 is the
/// first dialect that carries them, and a client that offers 0x0311 without a
/// pre-auth integrity context is rejected outright - the context is not
/// optional decoration, it is part of the dialect.
public enum NegotiateContext {
  public enum ContextType: UInt16 {
    case preauthIntegrityCapabilities = 0x0001
    case encryptionCapabilities = 0x0002
    case compressionCapabilities = 0x0003
    case netnameNegotiateContextId = 0x0005
    case transportCapabilities = 0x0006
    case rdmaTransformCapabilities = 0x0007
    case signingCapabilities = 0x0008
  }

  public enum HashAlgorithm: UInt16 {
    case sha512 = 0x0001
  }

  /// The order we send them in is the order of preference. GCM first: CCM has
  /// no usable implementation on Apple platforms (CommonCrypto exposes no CCM
  /// mode, CryptoKit has none), so offering it would mean negotiating a cipher
  /// we cannot run.
  public enum Cipher: UInt16 {
    case aes128ccm = 0x0001
    case aes128gcm = 0x0002
    case aes256ccm = 0x0003
    case aes256gcm = 0x0004

    public var isSupported: Bool { self == .aes128gcm }
  }

  /// One context, UNPADDED. The alignment belongs between contexts, not after
  /// each one: Samba 4.13 rejects the whole NEGOTIATE with
  /// STATUS_INVALID_PARAMETER when anything follows the last context, padding
  /// included, and says nothing about which byte it disliked. Measured by
  /// replaying a working `smbclient -m SMB3_11` negotiate and trimming it (the
  /// same packet passes at 182 bytes and fails at 184).
  static func encoded(type: ContextType, data: Data) -> Data {
    var out = Data()
    out += type.rawValue
    out += UInt16(data.count)
    out += UInt32(0)
    out += data
    return out
  }

  /// Joins contexts with the padding that goes BETWEEN them. The list starts
  /// on an 8-byte boundary, so aligning on the running length is the same as
  /// aligning on the message offset.
  static func list(_ contexts: [Data]) -> Data {
    var out = Data()
    for context in contexts {
      if !out.isEmpty { out += Data(count: padding(for: out.count)) }
      out += context
    }
    return out
  }

  static func padding(for count: Int) -> Int {
    (8 - count % 8) % 8
  }

  /// SMB2_PREAUTH_INTEGRITY_CAPABILITIES. The salt is ours and only has to be
  /// unpredictable; the server folds it into the hash chain.
  static func preauthIntegrity(salt: Data) -> Data {
    var data = Data()
    data += UInt16(1)                       // HashAlgorithmCount
    data += UInt16(salt.count)              // SaltLength
    data += HashAlgorithm.sha512.rawValue
    data += salt
    return encoded(type: .preauthIntegrityCapabilities, data: data)
  }

  /// SMB2_ENCRYPTION_CAPABILITIES.
  static func encryption(ciphers: [Cipher]) -> Data {
    var data = Data()
    data += UInt16(ciphers.count)
    for cipher in ciphers {
      data += cipher.rawValue
    }
    return encoded(type: .encryptionCapabilities, data: data)
  }

  /// What the server answered with. Only the two fields that change behaviour
  /// are read: everything else it may send is informational for us today, and
  /// guessing at a field we do not act on is how a parser starts lying.
  public struct ServerChoice {
    public var hashAlgorithm: HashAlgorithm?
    public var cipher: Cipher?
    /// A cipher the server picked that we cannot run. Kept apart from
    /// `cipher` on purpose: "no encryption" and "encryption we cannot speak"
    /// must not read the same at the call site.
    public var unsupportedCipher: UInt16?

    public init() {}
  }

  /// Parses the context list at `offset` in a NEGOTIATE response.
  public static func parse(_ data: Data, offset: Int, count: Int) -> ServerChoice {
    var choice = ServerChoice()
    var cursor = offset

    for _ in 0..<count {
      guard cursor + 8 <= data.count else { break }
      let reader = ByteReader(data)
      reader.seek(to: cursor)

      let rawType: UInt16 = reader.read()
      let length = Int(reader.read() as UInt16)
      _ = reader.read() as UInt32          // Reserved
      guard cursor + 8 + length <= data.count else { break }

      switch ContextType(rawValue: rawType) {
      case .preauthIntegrityCapabilities:
        guard length >= 6 else { break }
        _ = reader.read() as UInt16        // HashAlgorithmCount
        _ = reader.read() as UInt16        // SaltLength
        choice.hashAlgorithm = HashAlgorithm(rawValue: reader.read())
      case .encryptionCapabilities:
        guard length >= 4 else { break }
        _ = reader.read() as UInt16        // CipherCount
        let raw: UInt16 = reader.read()
        if let cipher = Cipher(rawValue: raw), cipher.isSupported {
          choice.cipher = cipher
        } else if raw != 0 {
          choice.unsupportedCipher = raw
        }
      default:
        break
      }

      cursor += 8 + length + padding(for: length)
    }

    return choice
  }
}
