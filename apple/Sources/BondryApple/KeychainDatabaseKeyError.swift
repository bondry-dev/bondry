import Security

public enum KeychainDatabaseKeyError: Error, Equatable, Sendable {
  case invalidConfiguration(KeychainDatabaseKeyConfiguration.Field)
  case invalidKeyLength(Int)
  case randomGenerationFailed(OSStatus)
  case missingKeychainEntitlement
  case keychainOperationFailed(OSStatus)
  case unexpectedKeychainResult
  case creationRaceCouldNotBeResolved
}
