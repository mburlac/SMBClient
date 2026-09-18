import XCTest
@testable import SMBClient

/// v2-236 M1, against the `samba-smb3only` fixture (`server min protocol =
/// SMB3`) on :3445. The RFC 4493 vectors prove the CMAC; only a real server
/// proves the KDF, the labels and the moment the key is installed - a wrong
/// answer there does not say "bad signature", it drops the connection.
///
/// Skipped when the fixture is not up: this is a developer's loop, and the
/// project's rule about silent skips is about CI, which sets the variable.
final class SMB3LiveTests: XCTestCase {

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

  /// M1's actual claim, on the plain Samba fixture: offered 3.0 and 3.0.2, the
  /// server picks 3.0.2, and every request after session setup is signed with
  /// AES-CMAC over the derived key. A wrong key is not a bad listing - it is
  /// the server dropping us - so reaching a directory IS the assertion.
  func testPlainSambaNowNegotiatesSMB302AndSignsWithCMAC() async throws {
    guard isReachable(port: 445) else { throw XCTSkip("samba fixture not running on :445") }

    let session = Session(host: "127.0.0.1", port: 445)
    try await session.connect()

    // Signing REQUIRED, deliberately: on a server that only enables it, the
    // CMAC path never runs and this test would pass without touching the code
    // it exists for.
    let negotiated = try await session.negotiate(securityMode: [.signingEnabled, .signingRequired])
    XCTAssertEqual(negotiated.dialectRevision, Negotiate.Dialects.smb302.rawValue,
                   "offered 3.0.2, got 0x\(String(negotiated.dialectRevision, radix: 16))")

    try await session.sessionSetup(username: "test", password: "test", requireSigning: true)
    XCTAssertEqual(session.signingAlgorithm, "AES-128-CMAC",
                   "the session is not signing with CMAC, so what follows proves nothing")

    try await session.treeConnect(path: "data")
    let files = try await session.queryDirectory(path: "", pattern: "*")
    XCTAssertFalse(files.isEmpty, "signed QUERY_DIRECTORY came back empty")

    try await session.treeDisconnect()
    try await session.logoff()
    session.disconnect()
  }

  /// The whole point of M1: a server that refuses 2.x outright lets us in.
  ///
  /// On :5445, not :3445. Samba's `server min protocol = SMB3` is an alias for
  /// **SMB3_11**, so the older fixture rejects a 3.0.2 client too and cannot
  /// prove anything about M1 - it is M2's row. `SMB3_00` is the one that means
  /// what the name suggests.
  func testSMB3OnlyServerAcceptsUsAndSignsWithCMAC() async throws {
    try requireFixture(port: 5445, named: "samba-smb30only")

    let session = Session(host: "127.0.0.1", port: 5445)
    try await session.connect()

    let negotiated = try await session.negotiate(securityMode: [.signingEnabled, .signingRequired])
    XCTAssertGreaterThanOrEqual(negotiated.dialectRevision,
                                Negotiate.Dialects.smb300.rawValue,
                                "a server pinned to SMB3 answered with a 2.x dialect")

    try await session.sessionSetup(username: "test", password: "test", requireSigning: true)
    XCTAssertEqual(session.signingAlgorithm, "AES-128-CMAC")

    // Every request from here is signed. A wrong key or a wrong algorithm is
    // not a bad list - it is the server dropping us, so reaching a listing at
    // all is the assertion.
    try await session.treeConnect(path: "data")
    let files = try await session.queryDirectory(path: "", pattern: "*")
    XCTAssertFalse(files.isEmpty, "signed QUERY_DIRECTORY came back empty")

    try await session.treeDisconnect()
    try await session.logoff()
    session.disconnect()
  }

  /// Before blaming the new code: does the EXISTING 2.x signing survive a
  /// server that requires signing? Samba defaults to `server signing = auto`,
  /// so a client that never asks is never checked - and the HMAC path may have
  /// been just as untested as the CMAC one.
  func testTwoPointXSigningAgainstAServerThatRequiresIt() async throws {
    guard isReachable(port: 445) else { throw XCTSkip("samba fixture not running on :445") }

    let session = Session(host: "127.0.0.1", port: 445)
    try await session.connect()
    defer { session.disconnect() }

    _ = try await session.negotiate(securityMode: [.signingEnabled, .signingRequired],
                                    dialects: [.smb202, .smb210])
    try await session.sessionSetup(username: "test", password: "test", requireSigning: true)
    XCTAssertEqual(session.signingAlgorithm, "HMAC-SHA256")

    try await session.treeConnect(path: "data")
    let files = try await session.queryDirectory(path: "", pattern: "*")
    XCTAssertFalse(files.isEmpty)
  }

  /// The old behaviour, kept as a measurement rather than a memory: the same
  /// server still refuses a client that offers only 2.x. Without this the test
  /// above could pass because the fixture stopped requiring SMB3.
  func testTheSameServerStillRefusesATwoPointXClient() async throws {
    try requireFixture(port: 5445, named: "samba-smb30only")

    let session = Session(host: "127.0.0.1", port: 5445)
    try await session.connect()
    defer { session.disconnect() }

    do {
      let response = try await session.negotiate(dialects: [.smb202, .smb210])
      XCTFail("the fixture accepted 2.x (dialect \(String(response.dialectRevision, radix: 16))) - it no longer proves anything")
    } catch {
      // Expected: STATUS_NOT_SUPPORTED.
    }
  }
}
