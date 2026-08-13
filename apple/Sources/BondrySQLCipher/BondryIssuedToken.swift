import CBondry

public struct BondryIssuedToken: Sendable, CustomDebugStringConvertible {
  public let metadata: BondryTokenMetadata

  private let storage: BondryIssuedTokenStorage

  public var debugDescription: String {
    "BondryIssuedToken(metadata: \(metadata), secret: [REDACTED])"
  }

  public func copySecret() -> String {
    storage.withSecretBytes { bytes in
      String(decoding: bytes, as: UTF8.self)
    }
  }

  public func withUnsafeSecretBytes<Result>(
    _ body: (UnsafeRawBufferPointer) throws -> Result
  ) rethrows -> Result {
    try storage.withSecretBytes(body)
  }

  init(storage: BondryIssuedTokenStorage) throws {
    metadata = try storage.withMetadataRecord { record in
      try BondryTokenMetadata(record: record)
    }
    try storage.validateSecret()
    storage.seal()
    self.storage = storage
  }
}

final class BondryIssuedTokenStorage: @unchecked Sendable {
  private let record: UnsafeMutablePointer<BondryIssuedTokenV1>
  private let secretOffset: Int
  private var secretLength = 0
  private var isSealed = false

  init() throws {
    guard let secretOffset = MemoryLayout<BondryIssuedTokenV1>.offset(of: \.secret) else {
      throw BondryEncryptedStoreError.invalidData
    }
    self.secretOffset = secretOffset
    record = .allocate(capacity: 1)
    record.initialize(to: BondryIssuedTokenV1())
  }

  deinit {
    _ = bondry_issued_token_clear_v1(record)
    record.deinitialize(count: 1)
    record.deallocate()
  }

  func withMutableRecord<Result>(
    _ body: (UnsafeMutablePointer<BondryIssuedTokenV1>) throws -> Result
  ) rethrows -> Result {
    precondition(!isSealed)
    return try body(record)
  }

  func withMetadataRecord<Result>(
    _ body: (BondryTokenMetadataV1) throws -> Result
  ) rethrows -> Result {
    try body(record.pointee.metadata)
  }

  func validateSecret() throws {
    precondition(!isSealed)
    let bytes = secretBytes()
    guard let end = bytes.firstIndex(of: 0), end > 0,
      String(bytes: bytes[..<end], encoding: .utf8) != nil
    else {
      throw BondryEncryptedStoreError.invalidData
    }
    secretLength = end
  }

  func seal() {
    precondition(!isSealed)
    isSealed = true
  }

  func withSecretBytes<Result>(
    _ body: (UnsafeRawBufferPointer) throws -> Result
  ) rethrows -> Result {
    precondition(isSealed)
    return try body(UnsafeRawBufferPointer(rebasing: secretBytes()[..<secretLength]))
  }

  private func secretBytes() -> UnsafeRawBufferPointer {
    UnsafeRawBufferPointer(
      start: UnsafeRawPointer(record).advanced(
        by: secretOffset
      ),
      count: Int(BONDRY_TOKEN_CAPACITY_V1)
    )
  }
}
