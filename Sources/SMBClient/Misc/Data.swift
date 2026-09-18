import Foundation

extension Data {
  init<T>(from value: T) {
    var value = value
    self = Swift.withUnsafeBytes(of: &value) { Data($0) }
  }

  /// `load` traps on a misaligned pointer, and a Data slice taken at an odd
  /// offset gives exactly that - which is how reading a negotiate context list
  /// (they sit wherever the previous one ended) crashed instead of parsing.
  /// Nothing here is ever hot enough for the aligned variant to matter.
  func to<T>(type: T.Type) -> T {
    return self.withUnsafeBytes { $0.loadUnaligned(as: T.self) }
  }
}

extension Data {
  init?(_ hex: String) {
    let len = hex.count / 2
    var data = Data(capacity: len)
    for i in 0..<len {
      let j = hex.index(hex.startIndex, offsetBy: i * 2)
      let k = hex.index(j, offsetBy: 2)
      let bytes = hex[j..<k]
      if var num = UInt8(bytes, radix: 16) {
        data.append(&num, count: 1)
      } else {
        return nil
      }
    }
    self = data
  }

  var hex: String {
    return reduce("") { $0 + String(format: "%02x", $1) }
  }
}
