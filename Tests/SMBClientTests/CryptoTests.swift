import XCTest
@testable import SMBClient

final class CryptoTests: XCTestCase {
  func testMD4() async throws {
    XCTAssertEqual(Crypto.md4("".data(using: .utf8)!).hex, "31d6cfe0d16ae931b73c59d7e0c089c0")
    XCTAssertEqual(Crypto.md4("a".data(using: .utf8)!).hex, "bde52cb31de33e46245e05fbdbd6fb24")
    XCTAssertEqual(Crypto.md4("abc".data(using: .utf8)!).hex, "a448017aaf21d8525fc10ae87aa6729d")
    XCTAssertEqual(Crypto.md4("message digest".data(using: .utf8)!).hex, "d9130a8164549fe818874806e1c7014b")
    XCTAssertEqual(Crypto.md4("abcdefghijklmnopqrstuvwxyz".data(using: .utf8)!).hex, "d79e1c308aa5bbcdeea8ed63df412da9")
    XCTAssertEqual(Crypto.md4("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".data(using: .utf8)!).hex, "043f8582f241db351ce627e153e7f0e4")
    XCTAssertEqual(Crypto.md4("12345678901234567890123456789012345678901234567890123456789012345678901234567890".data(using: .utf8)!).hex, "e33b4ddc9c38f2199c3e7b164fcc0536")
    XCTAssertEqual(Crypto.md4("test".data(using: .utf8)!).hex, "db346d691d7acc4dc2625db19f9e3f52")
  }

  // MARK: - SMB 3.x signing (v2-236 M1)

  private func hexData(_ hex: String) -> Data {
    var bytes = [UInt8]()
    var index = hex.startIndex
    while index < hex.endIndex {
      let next = hex.index(index, offsetBy: 2)
      bytes.append(UInt8(hex[index..<next], radix: 16)!)
      index = next
    }
    return Data(bytes)
  }

  /// RFC 4493's own vectors. An independent authority matters here: a signing
  /// function that is quietly wrong does not report a bad signature, it reports
  /// "the server closed the connection", and nothing points at the crypto.
  func testAESCMACRFC4493() {
    let key = hexData("2b7e151628aed2a6abf7158809cf4f3c")

    XCTAssertEqual(Crypto.aesCMAC(key: key, data: Data()).hex,
                   "bb1d6929e95937287fa37d129b756746",
                   "example 1: empty message")

    XCTAssertEqual(Crypto.aesCMAC(key: key, data: hexData("6bc1bee22e409f96e93d7e117393172a")).hex,
                   "070a16b46b4d4144f79bdd9dd04a287c",
                   "example 2: exactly one block")

    XCTAssertEqual(Crypto.aesCMAC(key: key, data: hexData(
      "6bc1bee22e409f96e93d7e117393172a" +
      "ae2d8a571e03ac9c9eb76fac45af8e51" +
      "30c81c46a35ce411")).hex,
      "dfa66747de9ae63030ca32611497c827",
      "example 3: a partial final block, which is the padded branch")

    XCTAssertEqual(Crypto.aesCMAC(key: key, data: hexData(
      "6bc1bee22e409f96e93d7e117393172a" +
      "ae2d8a571e03ac9c9eb76fac45af8e51" +
      "30c81c46a35ce411e5fbc1191a0a52ef" +
      "f69f2445df4f9b17ad2b417be66c3710")).hex,
      "51f0bebf7e3b9d92fc49741779363cfe",
      "example 4: four whole blocks, which is the K1 branch")
  }

  /// The KDF has no published vector we can borrow, so this pins the SHAPE of
  /// the input instead - the part that is easy to get wrong by reading. MS-SMB2
  /// passes label and context WITH their terminating nulls, and SP800-108 adds
  /// its own separator between them, so two consecutive nulls follow
  /// "SMB2AESCMAC". Whether the whole thing is right is decided by a real
  /// server accepting our signature, not here.
  func testSMB3SigningKeyDerivationShape() {
    let sessionKey = hexData("000102030405060708090a0b0c0d0e0f")

    let expectedInput = Data([0, 0, 0, 1])
      + Data("SMB2AESCMAC\0".utf8)
      + Data([0x00])
      + Data("SmbSign\0".utf8)
      + Data([0, 0, 0, 0x80])
    let expected = Data(Crypto.hmacSHA256(key: sessionKey, data: expectedInput).prefix(16))

    XCTAssertEqual(Crypto.smb3SigningKey(sessionKey: sessionKey), expected)
    XCTAssertEqual(Crypto.smb3SigningKey(sessionKey: sessionKey).count, 16)
    XCTAssertNotEqual(Crypto.smb3SigningKey(sessionKey: sessionKey), sessionKey,
                      "3.x does not sign with the session key itself")
  }
}
