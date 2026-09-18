import Foundation

public class Session {
  private var messageId = SequenceNumber<UInt64>()
  private var sessionId: UInt64 = 0
  private(set) var treeId: UInt32 = 0

  private var isAnonymous = false
  /// Readable so a test can prove the signing path actually RAN. A live test
  /// against a server that does not require signing passes without ever
  /// reaching the algorithm, and then proves nothing about it.
  private(set) var signingRequired = false
  private var signingKey: Data?
  /// v2-236 M1: which dialect the server picked. It decides the signing
  /// algorithm - 2.x is HMAC-SHA256 over the raw session key, 3.x is AES-CMAC
  /// over a DERIVED key - and neither server accepts the other's signature.
  private(set) var dialect: Negotiate.Dialects = .smb202

  // v2-236 M2 - 3.1.1.
  /// The pre-auth integrity chain (MS-SMB2 3.1.4.4.1). Every NEGOTIATE and
  /// SESSION_SETUP message feeds it, and the 3.1.1 keys come out of it.
  private var preauthHash = Data(count: 64)
  private(set) var negotiatedCipher: NegotiateContext.Cipher?
  /// A cipher the server chose that we cannot run, kept so the failure can say
  /// so instead of looking like "the server does not encrypt".
  private(set) var unsupportedCipher: UInt16?
  private var clientCipherKey: Data?
  private var serverCipherKey: Data?
  /// Nonces must never repeat under one key. Shared by reference with every
  /// `newSession()` off this connection, exactly like the message id.
  private var encryptionNonce = SequenceNumber<UInt64>()
  /// The per-connection opt-in. A share that demands encryption turns it on by
  /// itself at TREE_CONNECT regardless.
  public var requireEncryption = false
  private(set) var encryptData = false

  /// What the wire actually carries right now, for tests and for a log line.
  /// "none" while a test believes it is encrypting is the whole failure mode.
  var encryptionAlgorithm: String {
    guard encryptData, let cipher = negotiatedCipher else { return "none" }
    return cipher == .aes128gcm ? "AES-128-GCM" : "unsupported"
  }

  /// What `sign` would use right now, for tests and for a log line.
  var signingAlgorithm: String {
    guard signingKey != nil, signingRequired, !isAnonymous, !encryptData else { return "none" }
    return dialect.isSMB3 ? "AES-128-CMAC" : "HMAC-SHA256"
  }

  public private(set) var maxTransactSize: UInt32 = 0
  public private(set) var maxReadSize: UInt32 = 0
  public private(set) var maxWriteSize: UInt32 = 0

  public var server: String { connection.host }
  public private(set) var connectedTree: String?

  public var onDisconnected: (Error) -> Void {
    didSet {
      connection.onDisconnected = onDisconnected
    }
  }

  private let connection: Connection

  public convenience init(host: String) {
    self.init(Connection(host: host))
  }

  public convenience init(host: String, port: Int) {
    self.init(Connection(host: host, port: port))
  }

  private init(_ connection: Connection) {
    self.connection = connection
    onDisconnected = { _ in }
  }

  func newSession() -> Session {
    let session = Session(connection)

    session.messageId = messageId
    session.sessionId = sessionId
    session.treeId = 0

    session.signingRequired = signingRequired
    session.signingKey = signingKey
    session.dialect = dialect

    session.preauthHash = preauthHash
    session.negotiatedCipher = negotiatedCipher
    session.unsupportedCipher = unsupportedCipher
    session.clientCipherKey = clientCipherKey
    session.serverCipherKey = serverCipherKey
    session.encryptionNonce = encryptionNonce
    session.requireEncryption = requireEncryption
    session.encryptData = encryptData

    session.maxTransactSize = maxTransactSize
    session.maxReadSize = maxReadSize
    session.maxWriteSize = maxWriteSize

    return session
  }

  func treeAccessor(share: String) -> TreeAccessor {
    TreeAccessor(session: self, share: share)
  }

  public func connect() async throws {
    try await connection.connect()
  }

  public func disconnect() {
    connection.disconnect()
  }

  @discardableResult
  public func negotiate(
    securityMode: Negotiate.SecurityMode = [.signingEnabled],
    dialects: [Negotiate.Dialects] = [.smb202, .smb210, .smb300, .smb302, .smb311]
  ) async throws -> Negotiate.Response {
    // MS-SMB2 3.2.4.2.2.1: a client that offers 3.x states its capabilities.
    // largeMtu is the one that pays - it is what lets the server grant the
    // multi-credit read and write sizes the transfer code already asks for.
    let offers3x = dialects.contains { $0.rawValue >= Negotiate.Dialects.smb300.rawValue }
    // v2-236 M2: 3.1.1 without a pre-auth integrity context is not a lenient
    // 3.1.1, it is a rejected one - the context is part of the dialect.
    let offers311 = dialects.contains(.smb311)
    let request = Negotiate.Request(
      messageId: messageId.next(),
      securityMode: securityMode,
      capabilities: offers3x ? [.largeMtu, .encryption] : [],
      dialects: dialects,
      preauthSalt: offers311 ? Crypto.randomBytes(count: 32) : nil,
      ciphers: offers311 ? [.aes128gcm] : []
    )

    let response = try await send(request, preauth: offers311 ? .always : .none)

    dialect = Negotiate.Dialects(rawValue: response.dialectRevision) ?? .smb202

    if dialect.isSMB311 {
      let choice = NegotiateContext.parse(
        response.rawMessage,
        offset: Int(response.negotiateContextOffset),
        count: Int(response.negotiateContextCount)
      )
      negotiatedCipher = choice.cipher
      unsupportedCipher = choice.unsupportedCipher
    }

    signingRequired = response.securityMode.contains(.signingRequired) || (securityMode.contains(.signingRequired) && response.securityMode.contains(.signingEnabled))

    // v2-236 M2: 3.1.1 signs whether or not anybody asked. Samba grants the
    // session and then answers ACCESS_DENIED to the first TREE_CONNECT that
    // arrives unsigned - a denial that reads as a permissions problem and is
    // not one. `sign` still skips an anonymous session and an encrypted one.
    if dialect.isSMB311 {
      signingRequired = true
    }

    maxTransactSize = response.maxTransactSize
    maxReadSize = response.maxReadSize
    maxWriteSize = response.maxWriteSize

    return response
  }

  @discardableResult
  public func sessionSetup(
    username: String?,
    password: String?,
    domain: String? = nil,
    workstation: String? = nil,
    requireSigning: Bool = false
  ) async throws -> SessionSetup.Response {
    // 3.1.1 keeps hashing through session setup; earlier dialects have no
    // chain at all, and hashing into one they never use would be dead work.
    let preauthPhase: PreauthHashing = dialect.isSMB311 ? .requestAndInterimResponse : .none

    let negotiateMessage = NTLM.NegotiateMessage(
      domainName: domain,
      workstationName: workstation
    )
    let securityBuffer = negotiateMessage.encoded()

    let request = SessionSetup.Request(
      messageId: messageId.next(),
      sessionId: 0,
      securityMode: [requireSigning ? .signingRequired : .signingEnabled],
      capabilities: [],
      previousSessionId: 0,
      securityBuffer: securityBuffer
    )
    let response = try await send(request, preauth: preauthPhase)

    if NTStatus(response.header.status) == .moreProcessingRequired {
      let challengeMessage = NTLM.ChallengeMessage(data: response.buffer)

      let signingKey = Crypto.randomBytes(count: 16)
      let authenticateMessage = challengeMessage.authenticateMessage(
        username: username,
        password: password,
        domain: domain,
        workstation: workstation,
        negotiateMessage: securityBuffer,
        signingKey: signingKey
      )

      let request = SessionSetup.Request(
        messageId: messageId.next(),
        sessionId: response.header.sessionId,
        securityMode: [.signingEnabled],
        capabilities: [],
        previousSessionId: 0,
        securityBuffer: authenticateMessage.encoded()
      )

      // The hash is updated with THIS request and then stops: the keys are
      // derived from the value standing when the final request went out, not
      // from one that includes the success response.
      let response = try await send(request, preauth: preauthPhase)

      sessionId = response.header.sessionId

      isAnonymous = (username ?? "").isEmpty && (password ?? "").isEmpty
      // 3.x does not sign with the session key: MS-SMB2 3.1.4.2 derives one.
      //
      // The key is installed AFTER this send, so the final SESSION_SETUP goes
      // out unsigned - same as 2.x has always done. MS-SMB2 3.2.5.3 says it
      // SHOULD be signed, and installing the key before the send was tried:
      // Samba drops the connection. Since Samba accepts the unsigned form for
      // both dialects, this matches what already worked rather than what the
      // spec prefers. A stricter server (Windows, Synology) is where that
      // choice would show, and that row is not paid.
      if dialect.isSMB311 {
        self.signingKey = Crypto.smb311SigningKey(sessionKey: signingKey, preauthHash: preauthHash)
        clientCipherKey = Crypto.smb311ClientCipherKey(sessionKey: signingKey, preauthHash: preauthHash)
        serverCipherKey = Crypto.smb311ServerCipherKey(sessionKey: signingKey, preauthHash: preauthHash)

        // The transport unwraps the TRANSFORM_HEADER before anything reads an
        // SMB2 header off the front. The hook belongs HERE, where the key is
        // born, and captures it by value: hanging it off a Session instead
        // means it is missing on any connection that was never `connect()`ed
        // explicitly (the transport dials on first send), and stale on every
        // `newSession()` sharing this connection.
        connection.decrypt = Session.decrypter(key: serverCipherKey)
      } else {
        self.signingKey = dialect.isSMB3 ? Crypto.smb3SigningKey(sessionKey: signingKey) : signingKey
      }

      if requireEncryption {
        try enableEncryption()
      }

      return response
    } else {
      sessionId = response.header.sessionId
      return response
    }
  }

  @discardableResult
  public func logoff() async throws -> Logoff.Response {
    let request = Logoff.Request(
      messageId: messageId.next(),
      sessionId: sessionId
    )

    let response = try await send(request)

    sessionId = 0

    return response
  }

  public func enumShareAll() async throws -> [Share] {
    let treeAccessor = treeAccessor(share: "IPC$")
    let session = try await treeAccessor.session()

    let createResponse = try await session.create(
      desiredAccess: [.readData, .writeData, .appendData, .readAttributes],
      fileAttributes: [.normal],
      shareAccess: [.read, .write],
      createDisposition: .open,
      createOptions: [.nonDirectoryFile],
      name: "srvsvc"
    )

    try await session.bind(fileId: createResponse.fileId)
    let ioCtlResponse = try await session.netShareEnum(fileId: createResponse.fileId)

    let rpcResponse = DCERPC.Response(data: ioCtlResponse.buffer)
    let netShareEnumResponse = NetShareEnumResponse(data: rpcResponse.stub)

    let shares = netShareEnumResponse.shareInfo1.shareInfo

    try await session.close(fileId: createResponse.fileId)

    return shares.compactMap {
      var type = Share.ShareType(rawValue: $0.type & 0x0FFFFFFF)

      if $0.type & Share.ShareType.special.rawValue != 0 {
        type.insert(.special)
      }
      if $0.type & Share.ShareType.temporary.rawValue != 0 {
        type.insert(.temporary)
      }

      return Share(name: $0.name.value, comment: $0.comment.value, type: type)
    }
  }

  @discardableResult
  public func treeConnect(path: String) async throws -> TreeConnect.Response {
    let request = TreeConnect.Request(
      messageId: messageId.next(),
      sessionId: sessionId,
      path: #"\\\#(server)\\#(path)"#
    )

    let response = try await send(request)

    treeId = response.header.treeId
    connectedTree = path

    // MS-SMB2 3.2.5.5: a share marked SMB2_SHAREFLAG_ENCRYPT_DATA is not a
    // suggestion - everything after this point on that tree must be encrypted,
    // whether or not the user asked for it.
    if response.shareFlags.contains(.encryptData), !encryptData {
      try enableEncryption()
    }

    return response
  }

  @discardableResult
  public func treeDisconnect() async throws -> TreeDisconnect.Response {
    let request = TreeDisconnect.Request(
      messageId: messageId.next(),
      treeId: treeId,
      sessionId: sessionId
    )

    let response = try await send(request)

    treeId = 0
    connectedTree = nil

    return response
  }

  public func create(
    desiredAccess: FilePipePrinterAccessMask,
    fileAttributes: FileAttributes,
    shareAccess: Create.ShareAccess,
    createDisposition: Create.CreateDisposition,
    createOptions: Create.CreateOptions,
    name: String
  ) async throws -> Create.Response {
    let request = Create.Request(
      messageId: messageId.next(),
      treeId: treeId,
      sessionId: sessionId,
      desiredAccess: desiredAccess,
      fileAttributes: fileAttributes,
      shareAccess: shareAccess,
      createDisposition: createDisposition,
      createOptions: createOptions,
      name: name
    )

    return try await send(request)
  }

  public func read(fileId: Data, offset: UInt64) async throws -> Read.Response {
    try await read(fileId: fileId, offset: offset, length: maxReadSize)
  }

  public func read(fileId: Data, offset: UInt64, length: UInt32) async throws -> Read.Response {
    let readSize = min(length, maxReadSize)
    let creditSize = creditSize(size: readSize)

    let request = Read.Request(
      creditCharge: creditSize,
      messageId: messageId.next(count: UInt64(creditSize)),
      treeId: treeId,
      sessionId: sessionId,
      fileId: fileId,
      offset: offset,
      length: readSize
    )

    return try await send(request)
  }

  @discardableResult
  public func write(data: Data, fileId: Data, offset: UInt64) async throws -> Write.Response {
    try await write(data: data, fileId: fileId, offset: offset, length: maxWriteSize)
  }

  @discardableResult
  public func write(data: Data, fileId: Data, offset: UInt64, length: UInt32) async throws -> Write.Response {
    let writeSize = min(length, maxWriteSize)
    let creditSize = creditSize(size: writeSize)

    let request = Write.Request(
      creditCharge: creditSize,
      messageId: messageId.next(count: UInt64(creditSize)),
      treeId: treeId,
      sessionId: sessionId,
      fileId: fileId,
      offset: offset,
      data: data
    )

    return try await send(request)
  }

  @discardableResult
  public func close(fileId: Data) async throws -> Close.Response {
    let request = Close.Request(
      messageId: messageId.next(),
      treeId: treeId,
      sessionId: sessionId,
      fileId: fileId
    )

    return try await send(request)
  }

  public func queryDirectory(path: String, pattern: String) async throws -> [FileDirectoryInformation] {
    let createRequest = Create.Request(
      messageId: messageId.next(),
      treeId: treeId,
      sessionId: sessionId,
      desiredAccess: [.readData, .readAttributes, .synchronize],
      fileAttributes: [.directory],
      shareAccess: [.read, .write, .delete],
      createDisposition: .open,
      createOptions: [.directoryFile],
      name: path
    )

    let outputBufferLength = min(1048576, maxTransactSize)
    let creditSize = creditSize(size: outputBufferLength)
    let fileInformationClass = QueryDirectory.FileInformationClass.fileDirectoryInformation

    let queryDirectoryRequest = QueryDirectory.Request(
      creditCharge: creditSize,
      headerFlags: [.relatedOperations],
      messageId: messageId.next(count: UInt64(creditSize)),
      treeId: treeId,
      sessionId: sessionId,
      fileInformationClass: fileInformationClass,
      fileId: temporaryUUID,
      fileName: pattern,
      outputBufferLength: outputBufferLength
    )

    let (createResponse, queryDirectoryResponse) = try await send(createRequest, queryDirectoryRequest)

    var files: [FileDirectoryInformation] = queryDirectoryResponse.files()

    if NTStatus(createResponse.header.status) != .noMoreFiles {
      repeat {
        let fileId = createResponse.fileId

        let queryDirectoryRequest = QueryDirectory.Request(
          creditCharge: creditSize,
          messageId: messageId.next(count: UInt64(creditSize)),
          treeId: treeId,
          sessionId: sessionId,
          fileInformationClass: fileInformationClass,
          flags: [],
          fileId: fileId,
          fileName: pattern,
          outputBufferLength: outputBufferLength
        )

        let queryDirectoryResponse = try await send(queryDirectoryRequest)
        files.append(contentsOf: queryDirectoryResponse.files())

        if NTStatus(queryDirectoryResponse.header.status) == .noMoreFiles {
          break
        }
      } while true
    }

    try await close(fileId: createResponse.fileId)

    return files
  }

  public func fileStat(path: String) async throws -> Create.Response {
    let createRequest = Create.Request(
      messageId: messageId.next(),
      treeId: treeId,
      sessionId: sessionId,
      desiredAccess: [.readData, .readAttributes, .synchronize],
      fileAttributes: [],
      shareAccess: [.read, .write, .delete],
      createDisposition: .open,
      createOptions: [],
      name: path
    )
    let closeRequest = Close.Request(
      headerFlags: [.relatedOperations],
      messageId: messageId.next(),
      treeId: treeId,
      sessionId: sessionId,
      fileId: temporaryUUID
    )

    let (response, _) = try await send(createRequest, closeRequest)
    return response
  }

  public func existFile(path: String) async throws -> Bool {
    do {
      _ = try await fileStat(path: path)
      return true
    } catch let error as ErrorResponse {
      if NTStatus(error.header.status) == .objectNameNotFound {
        return false
      }
      throw error
    }
  }

  public func existDirectory(path: String) async throws -> Bool {
    do {
      let stat = try await fileStat(path: path)
      return stat.fileAttributes.contains(.directory)
    } catch let error as ErrorResponse {
      if NTStatus(error.header.status) == .objectNameNotFound {
        return false
      }
      throw error
    }
  }

  public func queryInfo(path: String, infoType: InfoType = .file, fileInfoClass: FileInfoClass = .fileAllInformation) async throws -> QueryInfo.Response {
    let createRequest = Create.Request(
      messageId: messageId.next(),
      treeId: treeId,
      sessionId: sessionId,
      desiredAccess: [.readAttributes],
      fileAttributes: [],
      shareAccess: [.read],
      createDisposition: .open,
      createOptions: [],
      name: path
    )
    let queryInfoRequest = QueryInfo.Request(
      headerFlags: [.relatedOperations],
      messageId: messageId.next(),
      treeId: treeId,
      sessionId: sessionId,
      infoType: infoType,
      fileInfoClass: fileInfoClass,
      fileId: temporaryUUID
    )
    let closeRequest = Close.Request(
      headerFlags: [.relatedOperations],
      messageId: messageId.next(),
      treeId: treeId,
      sessionId: sessionId,
      fileId: temporaryUUID
    )

    let (_, response, _) = try await send(createRequest, queryInfoRequest, closeRequest)
    return response
  }

  @discardableResult
  public func createDirectory(path: String) async throws -> Create.Response {
    let response = try await create(
      desiredAccess: [.readData, .readAttributes],
      fileAttributes: [],
      shareAccess: [.read, .write, .delete],
      createDisposition: .create,
      createOptions: [.directoryFile],
      name: path.precomposedStringWithCanonicalMapping
    )
    try await close(fileId: response.fileId)
    return response
  }

  public func deleteDirectory(path: String) async throws {
    let files = try await queryDirectory(path: path, pattern: "*")
    for file in files {
      guard file.fileName != "." && file.fileName != ".." else {
        continue
      }

      let subpath = Pathname.join(path, file.fileName)
      if file.fileAttributes.contains(.directory) {
        try await deleteDirectory(path: subpath)
      } else {
        try await deleteFile(path: subpath)
      }
    }

    let createRequest = Create.Request(
      messageId: messageId.next(),
      treeId: treeId,
      sessionId: sessionId,
      desiredAccess: [.readAttributes, .delete, .synchronize],
      fileAttributes: [.directory],
      shareAccess: [],
      createDisposition: .open,
      createOptions: [.directoryFile],
      name: path
    )
    let setInfoRequest = SetInfo.Request(
      headerFlags: [.relatedOperations],
      messageId: messageId.next(),
      treeId: treeId,
      sessionId: sessionId,
      fileId: temporaryUUID,
      infoType: .file,
      fileInformation: FileDispositionInformation(deletePending: true)
    )
    let closeRequest = Close.Request(
      headerFlags: [.relatedOperations],
      messageId: messageId.next(),
      treeId: treeId,
      sessionId: sessionId,
      fileId: temporaryUUID
    )

    _ = try await send(createRequest, setInfoRequest, closeRequest)
  }

  public func deleteFile(path: String) async throws {
    let createRequest = Create.Request(
      messageId: messageId.next(),
      treeId: treeId,
      sessionId: sessionId,
      desiredAccess: [.readAttributes, .delete, .synchronize],
      fileAttributes: [.normal],
      shareAccess: [],
      createDisposition: .open,
      createOptions: [],
      name: path
    )
    let setInfoRequest = SetInfo.Request(
      headerFlags: [.relatedOperations],
      messageId: messageId.next(),
      treeId: treeId,
      sessionId: sessionId,
      fileId: temporaryUUID,
      infoType: .file,
      fileInformation: FileDispositionInformation(deletePending: true)
    )
    let closeRequest = Close.Request(
      headerFlags: [.relatedOperations],
      messageId: messageId.next(),
      treeId: treeId,
      sessionId: sessionId,
      fileId: temporaryUUID
    )

    _ = try await send(createRequest, setInfoRequest, closeRequest)
  }

  public func move(from: String, to: String) async throws {
    let createRequest = Create.Request(
      messageId: messageId.next(),
      treeId: treeId,
      sessionId: sessionId,
      desiredAccess: [.readAttributes, .delete, .synchronize],
      fileAttributes: [.normal],
      shareAccess: [],
      createDisposition: .open,
      createOptions: [],
      name: from
    )
    let setInfoRequest = SetInfo.Request(
      headerFlags: [.relatedOperations],
      messageId: messageId.next(),
      treeId: treeId,
      sessionId: sessionId,
      fileId: temporaryUUID,
      infoType: .file,
      fileInformation: FileRenameInformation(fileName: to.precomposedStringWithCanonicalMapping)
    )
    let closeRequest = Close.Request(
      headerFlags: [.relatedOperations],
      messageId: messageId.next(),
      treeId: treeId,
      sessionId: sessionId,
      fileId: temporaryUUID
    )

    _ = try await send(createRequest, setInfoRequest, closeRequest)
  }

  @discardableResult
  public func setInfo(path: String, _ info: FileInformationClass) async throws -> SetInfo.Response {
    let createRequest = Create.Request(
      messageId: messageId.next(),
      treeId: treeId,
      sessionId: sessionId,
      desiredAccess: [.readAttributes, .writeAttributes, .synchronize],
      fileAttributes: [],
      shareAccess: [.read, .write, .delete],
      createDisposition: .open,
      createOptions: [],
      name: path
    )
    let setInfoRequest = SetInfo.Request(
      headerFlags: [.relatedOperations],
      messageId: messageId.next(),
      treeId: treeId,
      sessionId: sessionId,
      fileId: temporaryUUID,
      infoType: .file,
      fileInformation: info
    )
    let closeRequest = Close.Request(
      headerFlags: [.relatedOperations],
      messageId: messageId.next(),
      treeId: treeId,
      sessionId: sessionId,
      fileId: temporaryUUID
    )

    let (_, response, _) = try await send(createRequest, setInfoRequest, closeRequest)
    return response
  }

  @discardableResult
  public func flush(fileId: Data) async throws -> Flush.Response {
    let request = Flush.Request(
      messageId: messageId.next(),
      treeId: treeId,
      sessionId: sessionId,
      fileId: fileId
    )

    return try await send(request)
  }

  @discardableResult
  public func echo() async throws -> Echo.Response {
    let request = Echo.Request(
      messageId: messageId.next(),
      sessionId: sessionId
    )

    return try await send(request)
  }

  @discardableResult
  func bind(fileId: Data) async throws -> IOCtl.Response {
    let input = DCERPC.Bind(
      callID: 1,
      context: DCERPC.ContextList(
        items: [
          DCERPC.PresentationContext(
            contextID: 0,
            abstractSyntax: DCERPC.AbstractSyntax(),
            transferSyntaxes: [
              DCERPC.TransferSyntax()
            ]
          )
        ]
      )
    )

    let creditSize = creditSize(size: maxReadSize)
    let request = IOCtl.Request(
      creditCharge: creditSize,
      messageId: messageId.next(count: UInt64(creditSize)),
      treeId: treeId,
      sessionId: sessionId,
      ctlCode: .pipeTransceive,
      fileId: fileId,
      input: input.encoded(),
      output: Data()
    )

    return try await send(request)
  }

  func netShareEnum(fileId: Data) async throws -> IOCtl.Response {
    let netShareEnum = NetShareEnum(serverName: connection.host)

    let input = DCERPC.Request(
      callID: 0,
      opnum: .netrShareEnum,
      stub: netShareEnum.encoded()
    )

    let creditSize = creditSize(size: maxReadSize)
    let request = IOCtl.Request(
      creditCharge: creditSize,
      messageId: messageId.next(count: UInt64(creditSize)),
      treeId: treeId,
      sessionId: sessionId,
      ctlCode: .pipeTransceive,
      fileId: fileId,
      input: input.encoded(),
      output: Data()
    )

    return try await send(request)
  }

  /// How far the pre-auth chain follows a given exchange. NEGOTIATE hashes
  /// both halves; SESSION_SETUP hashes its requests and only the INTERIM
  /// responses - the success that ends the handshake is deliberately outside
  /// the hash the keys are derived from.
  enum PreauthHashing {
    case none
    case always
    case requestAndInterimResponse
  }

  private func send<Request: Message.Request>(_ message: Request) async throws -> Request.Response {
    try await send(message, preauth: .none)
  }

  private func send<Request: Message.Request>(
    _ message: Request,
    preauth: PreauthHashing
  ) async throws -> Request.Response {
    let packet = sign(message.encoded())

    if preauth != .none {
      preauthHash = Crypto.preauthHash(preauthHash, packet)
    }

    let data = try await connection.send(try transform(packet))

    switch preauth {
    case .none:
      break
    case .always:
      preauthHash = Crypto.preauthHash(preauthHash, data)
    case .requestAndInterimResponse:
      if data.count >= 64, NTStatus(Header(data: data[..<64]).status) == .moreProcessingRequired {
        preauthHash = Crypto.preauthHash(preauthHash, data)
      }
    }

    return Request.Response(data: data)
  }

  /// Turns on session encryption, or says exactly why it cannot. The two "no"
  /// answers are different and a caller that cannot tell them apart will blame
  /// the wrong side: no cipher at all means the server does not encrypt on
  /// this dialect, a cipher we do not support means it does and we cannot.
  func enableEncryption() throws {
    guard dialect.isSMB311 else {
      throw EncryptionError.dialectTooOld(dialect)
    }
    guard clientCipherKey != nil, serverCipherKey != nil else {
      throw EncryptionError.noSessionKey
    }
    if let unsupportedCipher {
      throw EncryptionError.unsupportedCipher(unsupportedCipher)
    }
    guard negotiatedCipher != nil else {
      throw EncryptionError.notOffered
    }
    encryptData = true
  }

  /// Wraps a signed packet in a TRANSFORM_HEADER when the session is
  /// encrypted. An encrypted message is not signed as well - the GCM tag IS
  /// the signature, and MS-SMB2 3.1.4.3 says so.
  private func transform(_ packet: Data) throws -> Data {
    guard encryptData, let key = clientCipherKey else { return packet }

    // GCM takes a 12-byte nonce; the header's field is 16 and the rest stays
    // zero. The counter is per-key and never reused, which is the whole
    // requirement - a repeat under one key loses the plaintext, not just the
    // integrity.
    var nonce = Data()
    nonce += encryptionNonce.next() + 1
    nonce += Data(count: 4)
    let nonceField = nonce + Data(count: 4)

    let framing = TransformHeader(
      signature: Data(count: 16),
      nonce: nonceField,
      originalMessageSize: UInt32(packet.count),
      sessionId: sessionId
    )
    let sealed = try Crypto.aesGCMSeal(
      key: key,
      nonce: nonce,
      plaintext: packet,
      aad: framing.associatedData()
    )

    let header = TransformHeader(
      signature: sealed.tag,
      nonce: nonceField,
      originalMessageSize: UInt32(packet.count),
      sessionId: sessionId
    )
    return header.encoded() + sealed.ciphertext
  }

  /// Only for a test that has to look at the bytes: a live listing cannot tell
  /// "we encrypted" from "the server tolerated plaintext".
  func debugTransform(_ packet: Data) throws -> Data { try transform(packet) }

  /// The transport's hook. Returns nil when the message claims to be encrypted
  /// and does not open - handing back the ciphertext would be read as an SMB2
  /// header and reported as some unrelated protocol error.
  private static func decrypter(key: Data?) -> (Data) -> Data? {
    { data in
      guard let header = TransformHeader(data: data) else { return data }
      guard let key else { return nil }
      return try? Crypto.aesGCMOpen(
        key: key,
        nonce: Data(header.nonce.prefix(12)),
        ciphertext: Data(data[TransformHeader.size...]),
        tag: header.signature,
        aad: header.associatedData()
      )
    }
  }



#if compiler(>=5.9)
  private func send<each Request: Message.Request>(_ messages: repeat each Request) async throws -> (repeat (each Request).Response) {
    var count = 0
    for _ in repeat each messages {
      count += 1
    }

    var packet = Data()
    var index = 0
    for message in repeat each messages {
      let data = message.encoded()
      let alignment = Data(count: 8 - data.count % 8)
      if index < count - 1 {
        let body = data + alignment
        var header = Header(data: body[..<64])
        let payload = data[64...]

        header.nextCommand = UInt32(body.count)

        packet += sign(header.encoded() + payload + alignment)
      } else {
        packet += sign(data + alignment)
      }

      index += 1
    }

    let responseData = try await connection.send(try transform(packet))
    let reader = ByteReader(responseData)

    var responses = [Data]()

    var header: Header
    var offset = 0

    repeat {
      responses.append(Data(responseData[offset...]))

      header = reader.read()

      offset += Int(header.nextCommand)
      reader.seek(to: offset)
    } while header.nextCommand != 0

    var iterator = 0
    func respond<R: Message.Request>(requestType: R.Type) -> R.Response {
      let response = R.Response(data: responses[iterator])
      iterator += 1
      return response
    }

    return (repeat respond(requestType: (each Request).self))
  }
#else
  private func send<R1: Message.Request, R2: Message.Request>(_ m1: R1, _ m2: R2) async throws -> (R1.Response, R2.Response) {
    let data = try await send(m1.encoded(), m2.encoded())
    let r1 = R1.Response(data: data)
    let r2 = R2.Response(data: Data(data[r1.header.nextCommand...]))
    return (r1, r2)
  }

  private func send<R1: Message.Request, R2: Message.Request, R3: Message.Request>(_ m1: R1, _ m2: R2, _ m3: R3) async throws -> (R1.Response, R2.Response, R3.Response) {
    let data = try await send(m1.encoded(), m2.encoded(), m3.encoded())
    let r1 = R1.Response(data: data)
    let r2 = R2.Response(data: Data(data[r1.header.nextCommand...]))
    let r3 = R3.Response(data: Data(data[r2.header.nextCommand...]))
    return (r1, r2, r3)
  }

  private func send(_ packets: Data...) async throws -> Data {
    return try await connection.send(
      try transform(packets.enumerated().reduce(into: Data()) {
        let alignment = Data(count: 8 - $1.element.count % 8)
        if $1.offset < packets.count - 1 {
          let packet = $1.element + alignment
          var header = Header(data: packet[..<64])
          let payload = $1.element[64...]

          header.nextCommand = UInt32(packet.count)

          $0 += sign(header.encoded() + payload + alignment)
        } else {
          $0 += sign($1.element + alignment)
        }
      })
    )
  }
#endif

  private func sign(_ packet: Data) -> Data {
    // An encrypted message is not signed as well: the GCM tag is the
    // signature (MS-SMB2 3.1.4.3), and the header inside the ciphertext goes
    // out with the signature field zeroed.
    if let signingKey, signingRequired, !isAnonymous, !encryptData {
      var header = Header(data: packet[..<64])
      let payload = packet[64...]

      header.flags = header.flags.union(.signed)

      let signed = header.encoded() + payload
      let signature = dialect.isSMB3
        ? Crypto.aesCMAC(key: signingKey, data: signed)[..<16]
        : Crypto.hmacSHA256(key: signingKey, data: signed)[..<16]
      header.signature = signature

      return header.encoded() + payload
    } else {
      return packet
    }
  }
}

public enum EncryptionError: Error {
  /// Encryption below 3.1.1 is AES-CCM, which has no implementation on Apple
  /// platforms - so we do not offer it and must not pretend to.
  case dialectTooOld(Negotiate.Dialects)
  case notOffered
  case unsupportedCipher(UInt16)
  case noSessionKey
}

// MessageIds must be unique per connection (MS-SMB2 3.2.4.1.3).
// Concurrent requests (parallel uploads on one session) call next()
// from different tasks, so allocation must be atomic - the previous
// unsynchronized increment minted duplicate MessageIds under load and
// the server dropped the connection mid-batch.
private class SequenceNumber<I: UnsignedInteger & FixedWidthInteger> {
  private var current: I = 0
  private let lock = NSLock()

  func next(count: I = 1) -> I {
    lock.lock()
    defer { lock.unlock() }
    let next = current
    current &+= count
    return next
  }
}

private func creditSize(size: UInt32) -> UInt16 {
  UInt16(truncatingIfNeeded: (size - 1) / 65536 + 1)
}
