import Foundation
import CommonCrypto

enum Crypto {
  public static func randomBytes(count: Int) -> Data {
    var bytes = [UInt8](repeating: 0, count: count)
    CCRandomGenerateBytes(&bytes, bytes.count)
    return Data(bytes)
  }

  public static func md4(_ data: Data) -> Data {
    var paddedData = data

    let messageLengthBits = UInt64(data.count * 8)

    paddedData.append(0x80)

    let messageLengthMod64 = paddedData.count % 64
    let padLength = messageLengthMod64 < 56 ? 56 - messageLengthMod64 : 120 - messageLengthMod64

    if padLength > 0 {
      paddedData.append(contentsOf: [UInt8](repeating: 0, count: padLength))
    }

    var lengthBytes = messageLengthBits.littleEndian
    withUnsafeBytes(of: &lengthBytes) { paddedData.append(contentsOf: $0) }

    var A: UInt32 = 0x67452301
    var B: UInt32 = 0xefcdab89
    var C: UInt32 = 0x98badcfe
    var D: UInt32 = 0x10325476

    let blockCount = paddedData.count / 64
    for i in 0..<blockCount {
      var X = [UInt32](repeating: 0, count: 16)
      for j in 0..<16 {
        let start = i * 64 + j * 4
        let wordBytes = paddedData.subdata(in: start..<start+4)
        X[j] = wordBytes.withUnsafeBytes { $0.load(as: UInt32.self).littleEndian }
      }

      let AA = A
      let BB = B
      let CC = C
      let DD = D

      func F(_ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 {
        return (x & y) | (~x & z)
      }

      func G(_ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 {
        return (x & y) | (x & z) | (y & z)
      }

      func H(_ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 {
        return x ^ y ^ z
      }

      func leftRotate(_ x: UInt32, by n: UInt32) -> UInt32 {
        return (x << n) | (x >> (32 - n))
      }

      A = leftRotate(A &+ F(B, C, D) &+ X[0], by: 3)
      D = leftRotate(D &+ F(A, B, C) &+ X[1], by: 7)
      C = leftRotate(C &+ F(D, A, B) &+ X[2], by: 11)
      B = leftRotate(B &+ F(C, D, A) &+ X[3], by: 19)
      A = leftRotate(A &+ F(B, C, D) &+ X[4], by: 3)
      D = leftRotate(D &+ F(A, B, C) &+ X[5], by: 7)
      C = leftRotate(C &+ F(D, A, B) &+ X[6], by: 11)
      B = leftRotate(B &+ F(C, D, A) &+ X[7], by: 19)
      A = leftRotate(A &+ F(B, C, D) &+ X[8], by: 3)
      D = leftRotate(D &+ F(A, B, C) &+ X[9], by: 7)
      C = leftRotate(C &+ F(D, A, B) &+ X[10], by: 11)
      B = leftRotate(B &+ F(C, D, A) &+ X[11], by: 19)
      A = leftRotate(A &+ F(B, C, D) &+ X[12], by: 3)
      D = leftRotate(D &+ F(A, B, C) &+ X[13], by: 7)
      C = leftRotate(C &+ F(D, A, B) &+ X[14], by: 11)
      B = leftRotate(B &+ F(C, D, A) &+ X[15], by: 19)

      let k2: UInt32 = 0x5a827999
      A = leftRotate(A &+ G(B, C, D) &+ X[0] &+ k2, by: 3)
      D = leftRotate(D &+ G(A, B, C) &+ X[4] &+ k2, by: 5)
      C = leftRotate(C &+ G(D, A, B) &+ X[8] &+ k2, by: 9)
      B = leftRotate(B &+ G(C, D, A) &+ X[12] &+ k2, by: 13)
      A = leftRotate(A &+ G(B, C, D) &+ X[1] &+ k2, by: 3)
      D = leftRotate(D &+ G(A, B, C) &+ X[5] &+ k2, by: 5)
      C = leftRotate(C &+ G(D, A, B) &+ X[9] &+ k2, by: 9)
      B = leftRotate(B &+ G(C, D, A) &+ X[13] &+ k2, by: 13)
      A = leftRotate(A &+ G(B, C, D) &+ X[2] &+ k2, by: 3)
      D = leftRotate(D &+ G(A, B, C) &+ X[6] &+ k2, by: 5)
      C = leftRotate(C &+ G(D, A, B) &+ X[10] &+ k2, by: 9)
      B = leftRotate(B &+ G(C, D, A) &+ X[14] &+ k2, by: 13)
      A = leftRotate(A &+ G(B, C, D) &+ X[3] &+ k2, by: 3)
      D = leftRotate(D &+ G(A, B, C) &+ X[7] &+ k2, by: 5)
      C = leftRotate(C &+ G(D, A, B) &+ X[11] &+ k2, by: 9)
      B = leftRotate(B &+ G(C, D, A) &+ X[15] &+ k2, by: 13)

      let k3: UInt32 = 0x6ed9eba1
      A = leftRotate(A &+ H(B, C, D) &+ X[0] &+ k3, by: 3)
      D = leftRotate(D &+ H(A, B, C) &+ X[8] &+ k3, by: 9)
      C = leftRotate(C &+ H(D, A, B) &+ X[4] &+ k3, by: 11)
      B = leftRotate(B &+ H(C, D, A) &+ X[12] &+ k3, by: 15)
      A = leftRotate(A &+ H(B, C, D) &+ X[2] &+ k3, by: 3)
      D = leftRotate(D &+ H(A, B, C) &+ X[10] &+ k3, by: 9)
      C = leftRotate(C &+ H(D, A, B) &+ X[6] &+ k3, by: 11)
      B = leftRotate(B &+ H(C, D, A) &+ X[14] &+ k3, by: 15)
      A = leftRotate(A &+ H(B, C, D) &+ X[1] &+ k3, by: 3)
      D = leftRotate(D &+ H(A, B, C) &+ X[9] &+ k3, by: 9)
      C = leftRotate(C &+ H(D, A, B) &+ X[5] &+ k3, by: 11)
      B = leftRotate(B &+ H(C, D, A) &+ X[13] &+ k3, by: 15)
      A = leftRotate(A &+ H(B, C, D) &+ X[3] &+ k3, by: 3)
      D = leftRotate(D &+ H(A, B, C) &+ X[11] &+ k3, by: 9)
      C = leftRotate(C &+ H(D, A, B) &+ X[7] &+ k3, by: 11)
      B = leftRotate(B &+ H(C, D, A) &+ X[15] &+ k3, by: 15)

      A = A &+ AA
      B = B &+ BB
      C = C &+ CC
      D = D &+ DD
    }

    var digest = Data()
    withUnsafeBytes(of: A.littleEndian) { digest.append(contentsOf: $0) }
    withUnsafeBytes(of: B.littleEndian) { digest.append(contentsOf: $0) }
    withUnsafeBytes(of: C.littleEndian) { digest.append(contentsOf: $0) }
    withUnsafeBytes(of: D.littleEndian) { digest.append(contentsOf: $0) }

    return digest
  }

  public static func hmacMD5(key: Data, data: Data) -> Data {
    let context = UnsafeMutablePointer<CCHmacContext>.allocate(capacity: 1)
    defer { context.deallocate() }
    CCHmacInit(context, CCHmacAlgorithm(kCCHmacAlgMD5), (key as NSData).bytes, size_t(key.count))
    CCHmacUpdate(context, (data as NSData).bytes, size_t(data.count))
    var hmac = Array<UInt8>(repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
    CCHmacFinal(context, &hmac)
    return Data(hmac)
  }

  public static func hmacSHA256(key: Data, data: Data) -> Data {
    let context = UnsafeMutablePointer<CCHmacContext>.allocate(capacity: 1)
    defer { context.deallocate() }
    CCHmacInit(context, CCHmacAlgorithm(kCCHmacAlgSHA256), (key as NSData).bytes, size_t(key.count))
    CCHmacUpdate(context, (data as NSData).bytes, size_t(data.count))
    var hmac = Array<UInt8>(repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
    CCHmacFinal(context, &hmac)
    return Data(hmac)
  }

  public static func rc4(key: Data, data: Data) -> Data {
    let cryptData = NSMutableData(length: Int((data.count)))!
    var numBytesEncrypted :size_t = 0
    CCCrypt(
      CCOperation(kCCEncrypt),
      CCAlgorithm(kCCAlgorithmRC4),
      0,
      (key as NSData).bytes,
      key.count,
      nil,
      (data as NSData).bytes,
      data.count,
      cryptData.mutableBytes,
      cryptData.length,
      &numBytesEncrypted
    )
    return cryptData as Data
  }

  // MARK: - SMB 3.x

  /// One AES-128 block, ECB, no padding. Only ever called on 16 bytes - it is
  /// the primitive CMAC is built out of, not a way to encrypt anything.
  private static func aesEncryptBlock(key: Data, block: Data) -> Data {
    var out = [UInt8](repeating: 0, count: kCCBlockSizeAES128)
    var moved = 0
    _ = key.withUnsafeBytes { keyPtr in
      block.withUnsafeBytes { inPtr in
        CCCrypt(
          CCOperation(kCCEncrypt),
          CCAlgorithm(kCCAlgorithmAES),
          CCOptions(kCCOptionECBMode),
          keyPtr.baseAddress, key.count,
          nil,
          inPtr.baseAddress, block.count,
          &out, out.count,
          &moved
        )
      }
    }
    return Data(out)
  }

  /// `data << 1` over the whole buffer, with RFC 4493's constant folded back in
  /// when the top bit was set.
  private static func shiftLeftOne(_ data: Data) -> Data {
    var out = [UInt8](repeating: 0, count: data.count)
    let bytes = [UInt8](data)
    let overflow = bytes[0] & 0x80
    for i in 0..<bytes.count {
      out[i] = bytes[i] << 1
      if i + 1 < bytes.count, bytes[i + 1] & 0x80 != 0 {
        out[i] |= 1
      }
    }
    if overflow != 0 {
      out[bytes.count - 1] ^= 0x87
    }
    return Data(out)
  }

  /// AES-128-CMAC (RFC 4493). SMB 3.0 / 3.0.2 sign with this; 2.x uses
  /// HMAC-SHA256 and neither server accepts the other's signature, so the
  /// dialect decides which one runs.
  ///
  /// CommonCrypto has no CMAC and neither does CryptoKit, so this is the
  /// algorithm itself. It is pinned to RFC 4493's own test vectors - a signing
  /// function that is quietly wrong fails as "the server dropped the
  /// connection", which says nothing about where to look.
  public static func aesCMAC(key: Data, data: Data) -> Data {
    let blockSize = kCCBlockSizeAES128

    let l = aesEncryptBlock(key: key, block: Data(count: blockSize))
    let k1 = shiftLeftOne(l)
    let k2 = shiftLeftOne(k1)

    let blockCount = (data.count + blockSize - 1) / blockSize
    let isComplete = data.count > 0 && data.count % blockSize == 0

    var lastBlock: Data
    if isComplete {
      lastBlock = data.suffix(blockSize)
      lastBlock = xor(lastBlock, k1)
    } else {
      var padded = blockCount > 0 ? Data(data.suffix(data.count - (blockCount - 1) * blockSize)) : Data()
      padded.append(0x80)
      padded.append(Data(count: blockSize - padded.count))
      lastBlock = xor(padded, k2)
    }

    var x = Data(count: blockSize)
    if blockCount > 1 {
      for i in 0..<(blockCount - 1) {
        let start = data.startIndex + i * blockSize
        let block = data[start..<(start + blockSize)]
        x = aesEncryptBlock(key: key, block: xor(x, Data(block)))
      }
    }
    return aesEncryptBlock(key: key, block: xor(x, lastBlock))
  }

  private static func xor(_ a: Data, _ b: Data) -> Data {
    Data(zip(a, b).map { $0 ^ $1 })
  }

  /// SP800-108 counter-mode KDF with HMAC-SHA256, the shape MS-SMB2 3.1.4.2
  /// asks for. `label` and `context` are passed WITH their terminating null,
  /// and the 0x00 between them is SP800-108's own separator - so the input
  /// carries two consecutive nulls after "SMB2AESCMAC", which is correct and
  /// looks like a bug every time somebody reads it.
  ///
  /// Only 128-bit outputs are needed (one PRF round), and asking for more
  /// would need the counter to advance - so it refuses rather than silently
  /// returning a short key.
  public static func sp800108CounterKDF(key: Data,
                                        label: Data,
                                        context: Data,
                                        outputBits: UInt32 = 128) -> Data {
    precondition(outputBits <= 256, "one HMAC-SHA256 round yields at most 256 bits")
    var input = Data()
    input.append(contentsOf: withUnsafeBytes(of: UInt32(1).bigEndian) { Array($0) })
    input.append(label)
    input.append(0x00)
    input.append(context)
    input.append(contentsOf: withUnsafeBytes(of: outputBits.bigEndian) { Array($0) })
    return Data(hmacSHA256(key: key, data: input).prefix(Int(outputBits) / 8))
  }

  /// MS-SMB2 3.1.4.2: the SMB 3.0 / 3.0.2 signing key. The session key is NOT
  /// the signing key on 3.x - signing the packet with it directly is how a
  /// 3.x handshake gets accepted and then every request rejected.
  public static func smb3SigningKey(sessionKey: Data) -> Data {
    sp800108CounterKDF(
      key: sessionKey,
      label: Data("SMB2AESCMAC\0".utf8),
      context: Data("SmbSign\0".utf8)
    )
  }
}
