import CBondry

public enum BondryEncryptedStoreError: Error, Equatable, Sendable {
  case incompatibleABI(expected: UInt32, actual: UInt32)
  case invalidFileURL
  case nullPointer
  case invalidLength
  case invalidUTF8
  case invalidPath
  case fileSystem
  case database
  case unsupportedSchema
  case invalidDatabaseKey
  case invalidData
  case unavailable
  case invalidHandle
  case internalFailure(Int32)

  init(status: BondryStatus) {
    switch status {
    case BONDRY_STATUS_NULL_POINTER:
      self = .nullPointer
    case BONDRY_STATUS_INVALID_LENGTH:
      self = .invalidLength
    case BONDRY_STATUS_INVALID_UTF8:
      self = .invalidUTF8
    case BONDRY_STATUS_INVALID_PATH:
      self = .invalidPath
    case BONDRY_STATUS_FILE_SYSTEM:
      self = .fileSystem
    case BONDRY_STATUS_DATABASE:
      self = .database
    case BONDRY_STATUS_UNSUPPORTED_SCHEMA:
      self = .unsupportedSchema
    case BONDRY_STATUS_INVALID_DATABASE_KEY:
      self = .invalidDatabaseKey
    case BONDRY_STATUS_INVALID_DATA:
      self = .invalidData
    case BONDRY_STATUS_UNAVAILABLE:
      self = .unavailable
    default:
      self = .internalFailure(status)
    }
  }
}
