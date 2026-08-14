import Foundation
import Security

public enum BondrySecretProviderError: Error, Equatable, Sendable {
  case emptyReference
  case invalidConfiguration
  case invalidSecretLength(Int)
  case secretNotFound
  case corruptStoredSecret
  case missingKeychainEntitlement
  case keychainOperationFailed(OSStatus)
  case updateRaceCouldNotBeResolved
}
