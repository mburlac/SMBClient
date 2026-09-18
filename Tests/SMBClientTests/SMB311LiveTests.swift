import XCTest
@testable import SMBClient

/// v2-236 M2, against the two fixtures M1 could not reach: `samba-smb3only`
/// on :3445 (`server min protocol = SMB3`, which in Samba means SMB3_11 and
/// refuses even a 3.0.2 client) and `samba-encrypted` on :4445 (`smb encrypt =
/// required`).
///
/// The vectors in `CryptoTests` prove the primitives. Only a server proves the
/// pre-auth hash chain, the labels, and the transform header - and it proves
/// them by answering at all: a wrong key there is not "bad signature", it is a
/// dropped connection or a message that will not open.
final class SMB311LiveTests: XCTestCase {

  private func requireFixture(port: UInt16, named name: String) throws {
    guard !isReachable(port: port) else { return }
    if ProcessInfo.processInfo.environment["EC_REQUIRE_FIXTURES"] == "1" {
      XCTFail("\(name) is not listening on \(port)")
    }
    throw XCTSkip("\(name) fixture not running on :\(port)")
  }

  private func isReachable(port: UInt16) -> Bool {
    let sock = socket(AF_INET, SOCK_STREAM, 0)
    guard sock >= 0 else { return false }
    defer { close(sock) }
    var addr = sockaddr_in()
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_port = port.bigEndian
    addr.sin_addr.s_addr = inet_addr("127.0.0.1")
    let result = withUnsafePointer(to: &addr) {
      $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
        connect(sock, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
      }
    }
    return result == 0
  }

  // MARK: - 3.1.1

  /// The row M1 explicitly left open: a server that demands SMB3_11 accepts
  /// us. Signing is required on purpose - on 3.1.1 the signing key comes out
  /// of the pre-auth hash, so a directory listing here is an assertion about
  /// the whole chain and not just about the dialect number.
  func testSMB311OnlyServerAcceptsUsAndSignsOverThePreauthHash() async throws {
    try requireFixture(port: 3445, named: "samba-smb3only")

    let session = Session(host: "127.0.0.1", port: 3445)
    try await session.connect()

    let negotiated = try await session.negotiate(securityMode: [.signingEnabled, .signingRequired])
    XCTAssertEqual(negotiated.dialectRevision, Negotiate.Dialects.smb311.rawValue,
                   "offered 3.1.1, got 0x\(String(negotiated.dialectRevision, radix: 16))")

    try await session.sessionSetup(username: "test", password: "test", requireSigning: true)
    XCTAssertEqual(session.signingAlgorithm, "AES-128-CMAC")

    try await session.treeConnect(path: "data")
    let files = try await session.queryDirectory(path: "", pattern: "*")
    XCTAssertFalse(files.isEmpty, "signed QUERY_DIRECTORY over a 3.1.1 session came back empty")
  }

  /// The negative control for the row above. A client that stops at 3.0.2 is
  /// exactly the pre-M2 build, and this fixture must refuse it - otherwise the
  /// test above passes on a server that would have taken anything.
  func testTheSameServerRefusesAClientThatStopsAt302() async throws {
    try requireFixture(port: 3445, named: "samba-smb3only")

    let session = Session(host: "127.0.0.1", port: 3445)
    try await session.connect()
    defer { session.disconnect() }

    do {
      try await session.negotiate(dialects: [.smb202, .smb210, .smb300, .smb302])
      XCTFail("a 3.0.2-only client was accepted by a server that requires SMB3_11")
    } catch {
      // Expected: NOT_SUPPORTED, or the connection dropped.
    }
  }

  /// 3.1.1 is the only dialect we encrypt on, and the refusal has to name the
  /// reason. Asking a 3.0.2 session to encrypt is a programming error, not a
  /// server problem, and it must not read as "the server declined".
  func testEncryptionIsRefusedBelow311WithItsOwnReason() async throws {
    try requireFixture(port: 5445, named: "samba-smb30only")

    let session = Session(host: "127.0.0.1", port: 5445)
    try await session.connect()
    defer { session.disconnect() }

    try await session.negotiate(dialects: [.smb202, .smb210, .smb300, .smb302])
    try await session.sessionSetup(username: "test", password: "test")

    XCTAssertThrowsError(try session.enableEncryption()) { error in
      guard case EncryptionError.dialectTooOld = error else {
        return XCTFail("expected dialectTooOld, got \(error)")
      }
    }
  }

  /// 3.1.1 signs even when nobody asked. Samba grants the session and then
  /// answers ACCESS_DENIED to the first unsigned TREE_CONNECT - a denial that
  /// reads as a permissions problem and is not one. This is the plain fixture,
  /// where `server signing = auto` means it demands nothing: the whole point is
  /// that we sign anyway.
  func testA311SessionSignsEvenWhenTheServerDoesNotAskForIt() async throws {
    guard isReachable(port: 445) else { throw XCTSkip("samba fixture not running on :445") }

    let session = Session(host: "127.0.0.1", port: 445)
    try await session.connect()

    // Signing is NOT requested: the default security mode only enables it.
    let negotiated = try await session.negotiate()
    XCTAssertEqual(negotiated.dialectRevision, Negotiate.Dialects.smb311.rawValue)

    try await session.sessionSetup(username: "test", password: "test")
    XCTAssertTrue(session.signingRequired, "a 3.1.1 session that does not sign is denied at tree connect")
    XCTAssertEqual(session.signingAlgorithm, "AES-128-CMAC")

    try await session.treeConnect(path: "data")
    let files = try await session.queryDirectory(path: "", pattern: "*")
    XCTAssertFalse(files.isEmpty)
  }

  // MARK: - Encryption

  /// The DoD row: a share that REQUIRES encryption. Everything after session
  /// setup goes out under a transform header, and a directory listing coming
  /// back means both cipher keys are right - they are derived separately, so
  /// a wrong one fails in one direction only.
  func testEncryptedShareListsWhenWeEncrypt() async throws {
    try requireFixture(port: 4445, named: "samba-encrypted")

    let session = Session(host: "127.0.0.1", port: 4445)
    session.requireEncryption = true
    try await session.connect()

    try await session.negotiate()
    try await session.sessionSetup(username: "test", password: "test")
    XCTAssertEqual(session.encryptionAlgorithm, "AES-128-GCM",
                   "the session is not encrypting, so what follows proves nothing")

    try await session.treeConnect(path: "data")
    let files = try await session.queryDirectory(path: "", pattern: "*")
    XCTAssertFalse(files.isEmpty, "encrypted QUERY_DIRECTORY came back empty")
  }

  /// The negative control for the row above: the same share, the same client,
  /// encryption off. If this passed, the test above would prove nothing about
  /// encryption - only that the share is reachable.
  func testTheSameShareRefusesUsWithoutEncryption() async throws {
    try requireFixture(port: 4445, named: "samba-encrypted")

    let session = Session(host: "127.0.0.1", port: 4445)
    try await session.connect()
    defer { session.disconnect() }

    do {
      try await session.negotiate()
      try await session.sessionSetup(username: "test", password: "test")
      try await session.treeConnect(path: "data")
      _ = try await session.queryDirectory(path: "", pattern: "*")
      XCTFail("a share with `smb encrypt = required` served an unencrypted session")
    } catch {
      // Expected: ACCESS_DENIED at tree connect, or earlier.
    }
  }

  /// The path EC actually takes, which is not the one the tests above take:
  /// `SMBClient.login` never calls `connect()` - the transport dials on first
  /// send - and every folder goes through a `TreeAccessor`, which runs on a
  /// `newSession()` off the same connection. Both of those broke decryption
  /// once, and neither is visible from a test that drives `Session` directly.
  func testEncryptionSurvivesTheClientEntryPointAndATreeAccessor() async throws {
    try requireFixture(port: 4445, named: "samba-encrypted")

    let client = SMBClient(host: "127.0.0.1", port: 4445)
    client.session.requireEncryption = true
    try await client.login(username: "test", password: "test")
    XCTAssertEqual(client.session.encryptionAlgorithm, "AES-128-GCM")

    let files = try await client.treeAccessor(share: "data").listDirectory(path: "")
    XCTAssertFalse(files.isEmpty, "encrypted listing through a TreeAccessor came back empty")
  }

  /// A round trip on a real session, for the one thing a live listing cannot
  /// distinguish: that we are the ones encrypting rather than the server
  /// tolerating plaintext.
  func testEncryptedBytesOnTheWireAreNotTheMessage() async throws {
    try requireFixture(port: 4445, named: "samba-encrypted")

    let session = Session(host: "127.0.0.1", port: 4445)
    session.requireEncryption = true
    try await session.connect()
    try await session.negotiate()
    try await session.sessionSetup(username: "test", password: "test")

    let packet = try XCTUnwrap(session.debugTransform(Data("\u{FE}SMB plaintext body".utf8)))
    XCTAssertTrue(TransformHeader.isEncrypted(packet), "no transform header on an encrypted session")
    XCTAssertFalse(packet.contains(Data("plaintext body".utf8)), "the body went out in the clear")
  }
}
