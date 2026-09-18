import XCTest
@testable import SMBClient

/// v2-236 M2. These pin the two framing rules that cost a live bisection to
/// find: a server that dislikes the context list answers
/// STATUS_INVALID_PARAMETER and names nothing, so the encoder has to be held in
/// place by something cheaper than a fixture.
final class NegotiateContextTests: XCTestCase {

  private func request(dialects: [Negotiate.Dialects],
                       ciphers: [NegotiateContext.Cipher]) -> Negotiate.Request {
    Negotiate.Request(
      messageId: 0,
      securityMode: [.signingEnabled],
      capabilities: [.largeMtu, .encryption],
      dialects: dialects,
      preauthSalt: Data(count: 32),
      ciphers: ciphers
    )
  }

  /// The one that bit: Samba 4.13 rejects the whole NEGOTIATE when ANY byte
  /// follows the last context, padding included. Windows tolerates it, which
  /// is why the spec reads as if it does not matter.
  func testNothingFollowsTheLastContext() {
    let r = request(dialects: [.smb202, .smb210, .smb300, .smb302, .smb311],
                    ciphers: [.aes128gcm])
    let packet = r.encoded()

    // Walk the list the way a server does, and land exactly on the end.
    var cursor = Int(r.negotiateContextOffset)
    for i in 0..<Int(r.negotiateContextCount) {
      let length = Int(Data(packet[(cursor + 2)..<(cursor + 4)]).to(type: UInt16.self))
      cursor += 8 + length
      if i < Int(r.negotiateContextCount) - 1 {
        cursor += NegotiateContext.padding(for: cursor)
      }
    }
    XCTAssertEqual(cursor, packet.count,
                   "\(packet.count - cursor) bytes after the last context; Samba refuses the message")
  }

  /// The other half of the same rule: contexts after the first still have to
  /// start 8-byte aligned, and the offset is measured from the SMB2 header.
  func testContextsAreAlignedAndOffsetIsFromTheHeader() {
    let r = request(dialects: [.smb202, .smb210, .smb300, .smb302, .smb311],
                    ciphers: [.aes128gcm])
    let packet = r.encoded()

    XCTAssertEqual(Int(r.negotiateContextOffset) % 8, 0)
    XCTAssertEqual(Int(r.negotiateContextOffset), 64 + 36 + 2 * 5 + r.padding.count)
    XCTAssertEqual(r.negotiateContextCount, 2)

    // The second context starts where the first ended, rounded up.
    let firstLength = Int(Data(packet[(Int(r.negotiateContextOffset) + 2)..<(Int(r.negotiateContextOffset) + 4)]).to(type: UInt16.self))
    var second = Int(r.negotiateContextOffset) + 8 + firstLength
    second += NegotiateContext.padding(for: second)
    XCTAssertEqual(second % 8, 0)
    XCTAssertEqual(Data(packet[second..<(second + 2)]).to(type: UInt16.self),
                   NegotiateContext.ContextType.encryptionCapabilities.rawValue)
  }

  /// A dialect list without 3.1.1 carries no contexts at all and keeps
  /// ClientStartTime where it was - the 2.x and 3.0.x wire format is
  /// unchanged by M2.
  func testNoContextsBelow311() {
    let r = request(dialects: [.smb202, .smb210, .smb300, .smb302], ciphers: [.aes128gcm])
    XCTAssertEqual(r.negotiateContextCount, 0)
    XCTAssertEqual(r.negotiateContextOffset, 0)
    XCTAssertTrue(r.negotiateContextList.isEmpty)
  }

  /// We must not advertise a cipher we cannot run: AES-CCM has no
  /// implementation on Apple platforms, and negotiating it would mean a
  /// session that sets up and then cannot send a single message.
  func testOnlyGCMIsOffered() {
    XCTAssertTrue(NegotiateContext.Cipher.aes128gcm.isSupported)
    XCTAssertFalse(NegotiateContext.Cipher.aes128ccm.isSupported)
    XCTAssertFalse(NegotiateContext.Cipher.aes256gcm.isSupported)
  }

  /// A server answering with a cipher we cannot speak must not read as "the
  /// server does not encrypt" - those two lead to opposite advice.
  func testAnUnsupportedServerCipherIsNotSilence() {
    var response = Data(count: 64)
    response += NegotiateContext.encryption(ciphers: [.aes128ccm])
    let choice = NegotiateContext.parse(response, offset: 64, count: 1)
    XCTAssertNil(choice.cipher)
    XCTAssertEqual(choice.unsupportedCipher, NegotiateContext.Cipher.aes128ccm.rawValue)
  }
}
