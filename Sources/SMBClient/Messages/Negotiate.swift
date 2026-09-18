import Foundation

public enum Negotiate {
  public struct Request: Message.Request {
    public typealias Response = Negotiate.Response

    public let header: Header
    public let structureSize: UInt16
    public let dialectCount: UInt16
    public let securityMode: SecurityMode
    public let reserved: UInt16
    public let capabilities: Capabilities
    public let clientGuid: UUID
    public let clientStartTime: UInt64
    public let dialects: [Dialects]
    public let padding: Data
    public let negotiateContextList: Data
    /// v2-236 M2: 3.1.1 reuses the 8 bytes 2.x spends on ClientStartTime for
    /// the context offset and count. Which of the two meanings applies is
    /// decided by the dialect list, not by a flag.
    public let negotiateContextOffset: UInt32
    public let negotiateContextCount: UInt16

    public init(
      headerFlags: Header.Flags = [],
      messageId: UInt64,
      securityMode: SecurityMode,
      capabilities: Capabilities = [],
      dialects: [Dialects],
      preauthSalt: Data? = nil,
      ciphers: [NegotiateContext.Cipher] = []
    ) {
      header = Header(
        creditCharge: 1,
        command: .negotiate,
        creditRequest: 0,
        flags: headerFlags,
        messageId: messageId,
        treeId: 0,
        sessionId: 0
      )

      structureSize  = 36
      dialectCount = UInt16(dialects.count)
      self.securityMode = securityMode
      reserved = 0
      self.capabilities = capabilities
      clientGuid = UUID()
      clientStartTime = 0
      self.dialects = dialects

      // Contexts start on an 8-byte boundary measured from the start of the
      // SMB2 header, not from the start of the body.
      let bodyEnd = 64 + 36 + dialects.count * 2
      if dialects.contains(.smb311), let preauthSalt {
        padding = Data(count: NegotiateContext.padding(for: bodyEnd))

        var contexts = [NegotiateContext.preauthIntegrity(salt: preauthSalt)]
        if !ciphers.isEmpty {
          contexts.append(NegotiateContext.encryption(ciphers: ciphers))
        }

        negotiateContextList = NegotiateContext.list(contexts)
        negotiateContextOffset = UInt32(bodyEnd + padding.count)
        negotiateContextCount = UInt16(contexts.count)
      } else {
        padding = Data(count: (dialects.count * 2) % 8)
        negotiateContextList = Data()
        negotiateContextOffset = 0
        negotiateContextCount = 0
      }
    }

    public func encoded() -> Data {
      var data = Data()

      data += header.encoded()

      data += structureSize
      data += dialectCount
      data += securityMode.rawValue
      data += reserved
      data += capabilities.rawValue
      data += Data(from: clientGuid)
      if negotiateContextCount > 0 {
        data += negotiateContextOffset
        data += negotiateContextCount
        data += UInt16(0)
      } else {
        data += clientStartTime
      }

      for dialect in dialects {
        data += dialect.rawValue
      }
      data += padding
      data += negotiateContextList

      return data
    }
  }

  public struct Response: Message.Response {
    public let header: Header
    public let structureSize: UInt16
    public let securityMode: SecurityMode
    public let dialectRevision: UInt16
    public let negotiateContextCount: UInt16
    public let serverGuid: UUID
    public let capabilities: Capabilities
    public let maxTransactSize: UInt32
    public let maxReadSize: UInt32
    public let maxWriteSize: UInt32
    public let systemTime: UInt64
    public let serverStartTime: UInt64
    public let securityBufferOffset: UInt16
    public let securityBufferLength: UInt16
    public let negotiateContextOffset: UInt32
    public let securityBuffer: Data
    /// v2-236 M2: the whole message, kept because the negotiate contexts are
    /// addressed by an offset FROM THE SMB2 HEADER - a parser handed only the
    /// body cannot find them.
    public let rawMessage: Data

    public init(data: Data) {
      rawMessage = data
      let reader = ByteReader(data)

      header = reader.read()

      structureSize = reader.read()
      securityMode = SecurityMode(rawValue: reader.read())
      dialectRevision = reader.read()
      negotiateContextCount = reader.read()
      serverGuid = reader.read()
      capabilities = Capabilities(rawValue: reader.read())
      maxTransactSize = reader.read()
      maxReadSize = reader.read()
      maxWriteSize = reader.read()
      systemTime = reader.read()
      serverStartTime = reader.read()
      securityBufferOffset = reader.read()
      securityBufferLength = reader.read()
      negotiateContextOffset = reader.read()
      securityBuffer = reader.read(from: Int(securityBufferOffset), count: Int(securityBufferLength))
    }
  }

  public struct SecurityMode: OptionSet, Sendable {
    public let rawValue: UInt16

    public init(rawValue: UInt16) {
      self.rawValue = rawValue
    }

    public static let signingEnabled = SecurityMode(rawValue: 0x0001)
    public static let signingRequired = SecurityMode(rawValue: 0x0002)
  }

  public struct Capabilities: OptionSet, Sendable {
    public let rawValue: UInt32

    public init(rawValue: UInt32) {
      self.rawValue = rawValue
    }

    public static let dfs = Capabilities(rawValue: 0x00000001)
    public static let leasing = Capabilities(rawValue: 0x00000002)
    public static let largeMtu = Capabilities(rawValue: 0x00000004)
    public static let multiChannel = Capabilities(rawValue: 0x00000008)
    public static let persistentHandles = Capabilities(rawValue: 0x00000010)
    public static let directoryLeasing = Capabilities(rawValue: 0x00000020)
    public static let encryption = Capabilities(rawValue: 0x00000040)
    public static let notifications = Capabilities(rawValue: 0x00000080)
  }

  public enum Dialects: UInt16 {
    case smb202 = 0x0202
    case smb210 = 0x0210
    case smb300 = 0x0300
    case smb302 = 0x0302
    case smb311 = 0x0311

    /// Signing algorithm, encryption and key derivation all change at 3.0.
    public var isSMB3: Bool { rawValue >= Dialects.smb300.rawValue }

    /// 3.1.1 changes the key derivation again (the pre-auth hash replaces the
    /// fixed context string) and is the only dialect we encrypt on.
    public var isSMB311: Bool { self == .smb311 }
  }
}
