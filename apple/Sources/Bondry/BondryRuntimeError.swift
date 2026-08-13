import CBondryRuntime

public enum BondryRuntimeError: Error, Equatable, Sendable {
  case incompatibleABI(expected: UInt32, actual: UInt32)
  case invalidFileURL
  case nullPointer
  case invalidLength
  case invalidUTF8
  case invalidPath
  case invalidArgument
  case bufferTooSmall
  case invalidJSON
  case payloadTooLarge
  case fileSystem
  case database
  case unsupportedSchema
  case invalidDatabaseKey
  case invalidData
  case unavailable
  case notFound
  case clientDisabled
  case tokenInactive
  case authenticationRejected
  case invalidTokenLifetime
  case entropyUnavailable
  case timeUnavailable
  case generationExhausted
  case alreadyExists
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
    case BONDRY_STATUS_INVALID_ARGUMENT:
      self = .invalidArgument
    case BONDRY_STATUS_BUFFER_TOO_SMALL:
      self = .bufferTooSmall
    case BONDRY_STATUS_INVALID_JSON:
      self = .invalidJSON
    case BONDRY_STATUS_PAYLOAD_TOO_LARGE:
      self = .payloadTooLarge
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
    case BONDRY_STATUS_NOT_FOUND:
      self = .notFound
    case BONDRY_STATUS_CLIENT_DISABLED:
      self = .clientDisabled
    case BONDRY_STATUS_TOKEN_INACTIVE:
      self = .tokenInactive
    case BONDRY_STATUS_AUTHENTICATION_REJECTED:
      self = .authenticationRejected
    case BONDRY_STATUS_INVALID_TOKEN_LIFETIME:
      self = .invalidTokenLifetime
    case BONDRY_STATUS_ENTROPY_UNAVAILABLE:
      self = .entropyUnavailable
    case BONDRY_STATUS_TIME_UNAVAILABLE:
      self = .timeUnavailable
    case BONDRY_STATUS_GENERATION_EXHAUSTED:
      self = .generationExhausted
    case BONDRY_STATUS_ALREADY_EXISTS:
      self = .alreadyExists
    default:
      self = .internalFailure(status)
    }
  }
}
