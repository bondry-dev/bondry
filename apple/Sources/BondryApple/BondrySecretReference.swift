import Darwin
import Foundation

public struct BondrySecretReference: Equatable, Hashable, Sendable {
  public let rawValue: String

  public init(_ rawValue: String) throws {
    guard !rawValue.isEmpty else {
      throw BondrySecretProviderError.emptyReference
    }
    self.rawValue = rawValue
  }
}

/// Secret bytes held in memory that is explicitly cleared on release.
public struct BondrySecretBytes: @unchecked Sendable, CustomDebugStringConvertible,
  CustomReflectable
{
  private let storage: BondrySecretStorage

  init(validating data: Data) throws {
    guard !data.isEmpty, data.count <= BondryResolvedSecret.maximumByteCount else {
      throw BondrySecretProviderError.invalidSecretLength(data.count)
    }
    storage = BondrySecretStorage(copying: data)
  }

  public var byteCount: Int {
    storage.count
  }

  /// Borrows secret bytes only for the duration of `body`.
  public func withUnsafeBytes<Result>(
    _ body: (UnsafeRawBufferPointer) throws -> Result
  ) rethrows -> Result {
    try storage.withUnsafeBytes(body)
  }

  public var debugDescription: String {
    "BondrySecretBytes([REDACTED])"
  }

  public var customMirror: Mirror {
    Mirror(self, children: ["bytes": "[REDACTED]"])
  }
}

public struct BondryResolvedSecret: Sendable, CustomDebugStringConvertible,
  CustomReflectable
{
  public static let maximumByteCount = 1_024

  public let current: BondrySecretBytes
  public let previous: BondrySecretBytes?

  public init(current: Data, previous: Data? = nil) throws {
    self.current = try BondrySecretBytes(validating: current)
    self.previous = try previous.map(BondrySecretBytes.init(validating:))
  }

  init(current: BondrySecretBytes, previous: BondrySecretBytes? = nil) {
    self.current = current
    self.previous = previous
  }

  public var debugDescription: String {
    "BondryResolvedSecret([REDACTED])"
  }

  public var customMirror: Mirror {
    Mirror(self, children: ["material": "[REDACTED]"])
  }
}

private final class BondrySecretStorage: @unchecked Sendable {
  let count: Int
  private let pointer: UnsafeMutableRawPointer

  init(copying data: Data) {
    count = data.count
    pointer = UnsafeMutableRawPointer.allocate(
      byteCount: data.count,
      alignment: MemoryLayout<UInt8>.alignment
    )
    data.withUnsafeBytes { source in
      pointer.copyMemory(from: source.baseAddress!, byteCount: source.count)
    }
  }

  deinit {
    _ = memset_s(pointer, count, 0, count)
    pointer.deallocate()
  }

  func withUnsafeBytes<Result>(
    _ body: (UnsafeRawBufferPointer) throws -> Result
  ) rethrows -> Result {
    try body(UnsafeRawBufferPointer(start: pointer, count: count))
  }
}
