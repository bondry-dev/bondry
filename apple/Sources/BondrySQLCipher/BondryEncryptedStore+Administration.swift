import CBondry
import Foundation

extension BondryEncryptedStore {
  public func createClient(named name: String) throws -> BondryClient {
    var record = BondryClientV1()
    let status = withUTF8Bytes(name) { nameBytes, nameLength in
      bondry_client_create_v1(handle, nameBytes, nameLength, &record)
    }
    try requireSuccess(status)
    return try BondryClient(record: record)
  }

  public func clients() throws -> [BondryClient] {
    try queryRecords { output, capacity, count in
      bondry_clients_list_v1(handle, output, capacity, count)
    }.map(BondryClient.init)
  }

  public func setClient(_ clientID: String, enabled: Bool) throws {
    let status = withUTF8Bytes(clientID) { idBytes, idLength in
      bondry_client_set_enabled_v1(handle, idBytes, idLength, enabled ? 1 : 0)
    }
    try requireSuccess(status)
  }

  public func issueToken(
    for clientID: String,
    label: String? = nil,
    expiresInSeconds: UInt64? = nil
  ) throws -> BondryIssuedToken {
    try issueOrRotateToken(
      identifier: clientID,
      label: label,
      expiresInSeconds: expiresInSeconds,
      rotate: false
    )
  }

  public func rotateToken(
    _ tokenID: String,
    label: String? = nil,
    expiresInSeconds: UInt64? = nil
  ) throws -> BondryIssuedToken {
    try issueOrRotateToken(
      identifier: tokenID,
      label: label,
      expiresInSeconds: expiresInSeconds,
      rotate: true
    )
  }

  public func revokeToken(_ tokenID: String) throws -> Bool {
    var changed: UInt8 = 0
    let status = withUTF8Bytes(tokenID) { idBytes, idLength in
      bondry_token_revoke_v1(handle, idBytes, idLength, &changed)
    }
    try requireSuccess(status)
    guard changed <= 1 else {
      throw BondryEncryptedStoreError.invalidData
    }
    return changed == 1
  }

  public func tokens(for clientID: String) throws -> [BondryTokenMetadata] {
    let records: [BondryTokenMetadataV1] = try withUTF8Bytes(clientID) { idBytes, idLength in
      try queryRecords { output, capacity, count in
        bondry_tokens_list_v1(
          handle,
          idBytes,
          idLength,
          output,
          capacity,
          count
        )
      }
    }
    return try records.map(BondryTokenMetadata.init)
  }

  public func authenticate(token: String) throws -> BondryPrincipal {
    var record = BondryPrincipalV1()
    let status = withUTF8Bytes(token) { tokenBytes, tokenLength in
      bondry_token_authenticate_v1(handle, tokenBytes, tokenLength, &record)
    }
    try requireSuccess(status)
    return try BondryPrincipal(record: record)
  }

  public func authenticate(token: BondryIssuedToken) throws -> BondryPrincipal {
    var record = BondryPrincipalV1()
    let status = token.withUnsafeSecretBytes { tokenBytes in
      let tokenBytes = tokenBytes.bindMemory(to: UInt8.self)
      return bondry_token_authenticate_v1(
        handle,
        tokenBytes.baseAddress,
        tokenBytes.count,
        &record
      )
    }
    try requireSuccess(status)
    return try BondryPrincipal(record: record)
  }

  public func recentAuditEvents(limit: UInt32) throws -> [BondryAuditEvent] {
    let records: [BondryAuditEventV1] = try queryRecords { output, capacity, count in
      bondry_audit_recent_v1(handle, limit, output, capacity, count)
    }
    return try records.map(BondryAuditEvent.init)
  }

  public func auditEvents(for principalID: String, limit: UInt32) throws -> [BondryAuditEvent] {
    let records: [BondryAuditEventV1] = try withUTF8Bytes(principalID) { idBytes, idLength in
      try queryRecords { output, capacity, count in
        bondry_audit_for_principal_v1(
          handle,
          idBytes,
          idLength,
          limit,
          output,
          capacity,
          count
        )
      }
    }
    return try records.map(BondryAuditEvent.init)
  }

  public func addGrant(
    principalID: String,
    adapterID: String,
    capabilityID: String
  ) throws -> Bool {
    try updateGrant(
      principalID: principalID,
      adapterID: adapterID,
      capabilityID: capabilityID,
      add: true
    )
  }

  public func removeGrant(
    principalID: String,
    adapterID: String,
    capabilityID: String
  ) throws -> Bool {
    try updateGrant(
      principalID: principalID,
      adapterID: adapterID,
      capabilityID: capabilityID,
      add: false
    )
  }

  public func grants(for principalID: String) throws -> [BondryCapabilityGrant] {
    let records: [BondryGrantV1] = try withUTF8Bytes(principalID) { idBytes, idLength in
      try queryRecords { output, capacity, count in
        bondry_grants_list_v1(
          handle,
          idBytes,
          idLength,
          output,
          capacity,
          count
        )
      }
    }
    return try records.map(BondryCapabilityGrant.init)
  }

  private func issueOrRotateToken(
    identifier: String,
    label: String?,
    expiresInSeconds: UInt64?,
    rotate: Bool
  ) throws -> BondryIssuedToken {
    if let expiresInSeconds {
      guard expiresInSeconds > 0 else {
        throw BondryEncryptedStoreError.invalidTokenLifetime
      }
    }
    let storage = try BondryIssuedTokenStorage()
    let status = withUTF8Bytes(identifier) { idBytes, idLength in
      withOptionalUTF8Bytes(label) { labelBytes, labelLength in
        storage.withMutableRecord { output in
          if rotate {
            bondry_token_rotate_v1(
              handle,
              idBytes,
              idLength,
              labelBytes,
              labelLength,
              expiresInSeconds ?? 0,
              expiresInSeconds == nil ? 0 : 1,
              output
            )
          } else {
            bondry_token_issue_v1(
              handle,
              idBytes,
              idLength,
              labelBytes,
              labelLength,
              expiresInSeconds ?? 0,
              expiresInSeconds == nil ? 0 : 1,
              output
            )
          }
        }
      }
    }
    try requireSuccess(status)
    return try BondryIssuedToken(storage: storage)
  }

  private func updateGrant(
    principalID: String,
    adapterID: String,
    capabilityID: String,
    add: Bool
  ) throws -> Bool {
    var changed: UInt8 = 0
    let status = withUTF8Bytes(principalID) { principalBytes, principalLength in
      withUTF8Bytes(adapterID) { adapterBytes, adapterLength in
        withUTF8Bytes(capabilityID) { capabilityBytes, capabilityLength in
          if add {
            bondry_grant_add_v1(
              handle,
              principalBytes,
              principalLength,
              adapterBytes,
              adapterLength,
              capabilityBytes,
              capabilityLength,
              &changed
            )
          } else {
            bondry_grant_remove_v1(
              handle,
              principalBytes,
              principalLength,
              adapterBytes,
              adapterLength,
              capabilityBytes,
              capabilityLength,
              &changed
            )
          }
        }
      }
    }
    try requireSuccess(status)
    guard changed <= 1 else {
      throw BondryEncryptedStoreError.invalidData
    }
    return changed == 1
  }
}

func requireSuccess(_ status: BondryStatus) throws {
  guard status == BONDRY_STATUS_OK else {
    throw BondryEncryptedStoreError(status: status)
  }
}

func queryRecords<Record>(
  _ query: (UnsafeMutablePointer<Record>?, Int, UnsafeMutablePointer<Int>) -> BondryStatus
) throws -> [Record] {
  var requiredCount = 0
  try requireSuccess(query(nil, 0, &requiredCount))
  guard requiredCount > 0 else {
    return []
  }

  var capacity = requiredCount
  for _ in 0..<4 {
    let records = UnsafeMutablePointer<Record>.allocate(capacity: capacity)
    defer { records.deallocate() }
    var returnedCount = capacity
    let status = query(records, capacity, &returnedCount)
    if status == BONDRY_STATUS_OK {
      guard returnedCount >= 0, returnedCount <= capacity else {
        throw BondryEncryptedStoreError.invalidData
      }
      return Array(UnsafeBufferPointer(start: records, count: returnedCount))
    }
    guard status == BONDRY_STATUS_BUFFER_TOO_SMALL, returnedCount > capacity else {
      throw BondryEncryptedStoreError(status: status)
    }
    capacity = returnedCount
  }
  throw BondryEncryptedStoreError.bufferTooSmall
}

func withUTF8Bytes<Result>(
  _ value: String,
  _ body: (UnsafePointer<UInt8>, Int) throws -> Result
) rethrows -> Result {
  let bytes = Array(value.utf8)
  if bytes.isEmpty {
    var empty: UInt8 = 0
    return try withUnsafePointer(to: &empty) { pointer in
      try body(pointer, 0)
    }
  }
  return try bytes.withUnsafeBufferPointer { buffer in
    try body(buffer.baseAddress!, buffer.count)
  }
}

func withOptionalUTF8Bytes<Result>(
  _ value: String?,
  _ body: (UnsafePointer<UInt8>?, Int) throws -> Result
) rethrows -> Result {
  guard let value else {
    return try body(nil, 0)
  }
  return try withUTF8Bytes(value, body)
}
