public enum BondryCredentialProtection: Equatable, Sendable {
  case accessControlled
  case hostBound
  case hardwareBound
  case external
}

public enum BondryCredentialStoreAccess: Equatable, Sendable {
  case readOnly
  case readWrite
}

public struct BondryCredentialStoreCapabilities: Equatable, Sendable {
  public let protection: BondryCredentialProtection
  public let access: BondryCredentialStoreAccess
  public let supportsUnattendedAccess: Bool

  public init(
    protection: BondryCredentialProtection,
    access: BondryCredentialStoreAccess,
    supportsUnattendedAccess: Bool
  ) {
    self.protection = protection
    self.access = access
    self.supportsUnattendedAccess = supportsUnattendedAccess
  }
}

public enum BondryCredentialStoreError: Error, Equatable, Sendable {
  case incompatibleABI(expected: UInt32, actual: UInt32)
  case invalidDirectoryURL
  case nullPointer
  case invalidLength
  case invalidUTF8
  case invalidPath
  case invalidArgument
  case bufferTooSmall
  case invalidMaterial
  case unavailable
  case unsafeStorage
  case accessDenied
  case readOnly
  case invalidHandle
  case invalidCapabilities
  case internalFailure(Int32)
}
