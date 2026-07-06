import Foundation

public class TreeAccessor {
  public let share: String
  private let session: Session
  // Single-flights the lazy TREE_CONNECT below. Without it, the first
  // N concurrent operations on a fresh accessor all saw treeId == 0
  // and each issued its own TREE_CONNECT on the shared session; the
  // racing responses clobbered treeId and the in-flight requests
  // failed with sharing violations / dropped connections.
  private let connectSemaphore = Semaphore(value: 1)

  init(session: Session, share: String) {
    self.session = session.newSession()
    self.share = share
  }

  deinit {
    let session = self.session
    Task {
      try await session.treeDisconnect()
    }
  }

  public func listDirectory(path: String, pattern: String = "*") async throws -> [File] {
    let files = try await session().queryDirectory(path: Pathname.normalize(path), pattern: pattern)
    return files.map { File(fileInfo: $0) }
  }

  public func createDirectory(path: String) async throws {
    try await session().createDirectory(path: Pathname.normalize(path.precomposedStringWithCanonicalMapping))
  }

  public func rename(from: String, to: String) async throws {
    try await move(from: Pathname.normalize(from), to: Pathname.normalize(to))
  }

  public func move(from: String, to: String) async throws {
    try await session().move(from: Pathname.normalize(from), to: Pathname.normalize(to.precomposedStringWithCanonicalMapping))
  }

  public func deleteDirectory(path: String) async throws {
    try await session().deleteDirectory(path: Pathname.normalize(path))
  }

  public func deleteFile(path: String) async throws {
    try await session().deleteFile(path: Pathname.normalize(path))
  }

  public func fileStat(path: String) async throws -> FileStat {
    let response = try await session().fileStat(path: Pathname.normalize(path))
    return FileStat(response)
  }

  public func existFile(path: String) async throws -> Bool {
    try await session().existFile(path: Pathname.normalize(path))
  }

  public func existDirectory(path: String) async throws -> Bool {
    try await session().existDirectory(path: Pathname.normalize(path))
  }

  public func fileInfo(path: String) async throws -> FileAllInformation {
    let response = try await session().queryInfo(path: Pathname.normalize(path))
    return FileAllInformation(data: response.buffer)
  }

  public func download(path: String) async throws -> Data {
    let fileReader = try await fileReader(path: Pathname.normalize(path))

    let data = try await fileReader.download()
    try await fileReader.close()

    return data
  }

  public func upload(content: Data, path: String) async throws {
    try await upload(content: content, path: Pathname.normalize(path), progressHandler: { _ in })
  }

  public func upload(content: Data, path: String, progressHandler: (_ progress: Double) -> Void) async throws {
    let fileWriter = try await fileWriter(path: Pathname.normalize(path))

    try await fileWriter.upload(data: content, progressHandler: progressHandler)
    try await fileWriter.close()
  }

  public func upload(fileHandle: FileHandle, path: String) async throws {
    try await upload(fileHandle: fileHandle, path: path, progressHandler: { _ in })
  }

  public func upload(fileHandle: FileHandle, path: String, progressHandler: (_ progress: Double) -> Void) async throws {
    let fileWriter = try await fileWriter(path: Pathname.normalize(path))

    try await fileWriter.upload(fileHandle: fileHandle, progressHandler: progressHandler)
    try await fileWriter.close()

    await fileWriter.restoreFileAttributes(fileHandle, path)
  }

  public func upload(localPath: URL, remotePath path: String) async throws {
    try await upload(localPath: localPath, remotePath: path, progressHandler: { _, _, _ in })
  }

  public func upload(
    localPath: URL,
    remotePath path: String,
    progressHandler: (_ completedFiles: Int, _ fileBeingTransferred: URL, _ bytesSent: Int64) -> Void
  ) async throws {
    let fileWriter = try await fileWriter(path: Pathname.normalize(path))

    try await fileWriter.upload(localPath: localPath, progressHandler: progressHandler)
    try await fileWriter.close()
  }

  public func fileReader(path: String) async throws -> FileReader {
    FileReader(session: try await session(), path: Pathname.normalize(path))
  }

  public func fileWriter(path: String) async throws -> FileWriter {
    FileWriter(session: try await session(), path: Pathname.normalize(path))
  }

  public func availableSpace() async throws -> UInt64 {
    let response = try await session().queryInfo(path: "", infoType: .fileSystem, fileInfoClass: .fileFsSizeInformation)

    let sizeInformation = FileFsSizeInformation(data: response.buffer)
    let availableAllocationUnits = sizeInformation.availableAllocationUnits
    let sectorsPerAllocationUnit = sizeInformation.sectorsPerAllocationUnit
    let bytesPerSector = sizeInformation.bytesPerSector

    let bytesPerAllocationUnit = UInt64(sectorsPerAllocationUnit * bytesPerSector)
    let availableSpaceBytes = availableAllocationUnits * bytesPerAllocationUnit

    return availableSpaceBytes
  }

  public func keepAlive() async throws -> Echo.Response {
    try await session().echo()
  }

  func session() async throws -> Session {
    // Fast path: already connected.
    if session.treeId != 0 { return session }
    await connectSemaphore.wait()
    defer { connectSemaphoreSignal() }
    // Re-check under the semaphore - a concurrent caller may have
    // connected while we waited.
    if session.treeId == 0 {
      try await session.treeConnect(path: share)
    }
    return session
  }

  private func connectSemaphoreSignal() {
    let semaphore = connectSemaphore
    Task { await semaphore.signal() }
  }
}
