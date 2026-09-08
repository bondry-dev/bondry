use rusqlite::{Connection, Transaction};

const SELECT_USAGE: &str = "SELECT records, charged_bytes FROM storage_usage WHERE table_name = ?1";

pub(crate) fn read(connection: &Connection, table: &str) -> rusqlite::Result<(i64, i64)> {
    let (records, bytes): (i64, i64) = connection
        .prepare_cached(SELECT_USAGE)?
        .query_row([table], |row| Ok((row.get(0)?, row.get(1)?)))?;
    let minimum = records
        .checked_mul(if table == "delivery_log" { 512 } else { 96 })
        .ok_or(rusqlite::Error::InvalidQuery)?;
    if records < 0
        || bytes < minimum
        || (records == 0 && bytes != 0)
        || (table == "delivery_log" && bytes != minimum)
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok((records, bytes))
}

pub(crate) fn initialize(transaction: &Transaction<'_>) -> rusqlite::Result<()> {
    transaction.execute_batch(
        "CREATE TABLE storage_usage (
             table_name TEXT PRIMARY KEY NOT NULL
                 CHECK (table_name IN ('delivery_log', 'webhook_dedup')),
             records INTEGER NOT NULL CHECK (typeof(records) = 'integer' AND records >= 0),
             charged_bytes INTEGER NOT NULL
                 CHECK (typeof(charged_bytes) = 'integer' AND charged_bytes >= 0),
             CHECK (records != 0 OR charged_bytes = 0),
             CHECK (charged_bytes >= records * 96),
             CHECK (table_name != 'delivery_log' OR charged_bytes = records * 512)
         );",
    )?;
    refresh(transaction)?;
    for table in ["delivery_log", "webhook_dedup"] {
        create_triggers(transaction, table)?;
    }
    Ok(())
}

pub(crate) fn refresh(transaction: &Transaction<'_>) -> rusqlite::Result<()> {
    transaction.execute("DELETE FROM storage_usage", [])?;
    for (table, valid_charge) in [
        ("delivery_log", "charged_bytes = 512"),
        ("webhook_dedup", "charged_bytes >= 96"),
    ] {
        transaction.execute(
            &format!(
                "INSERT INTO storage_usage (table_name, records, charged_bytes)
                 SELECT ?1, COUNT(*),
                     CASE WHEN COUNT(*) = COUNT(CASE
                         WHEN typeof(charged_bytes) = 'integer' AND {valid_charge} THEN 1 END)
                     THEN COALESCE(SUM(charged_bytes), 0) END
                 FROM {table}"
            ),
            [table],
        )?;
    }
    Ok(())
}

pub(crate) fn create_triggers(transaction: &Transaction<'_>, table: &str) -> rusqlite::Result<()> {
    transaction.execute_batch(&format!(
        "CREATE TRIGGER {table}_usage_insert AFTER INSERT ON {table} BEGIN
             UPDATE storage_usage
             SET records = records + 1, charged_bytes = charged_bytes + NEW.charged_bytes
             WHERE table_name = '{table}';
             SELECT RAISE(ABORT, 'storage usage unavailable') WHERE changes() != 1;
         END;
         CREATE TRIGGER {table}_usage_delete AFTER DELETE ON {table} BEGIN
             UPDATE storage_usage
             SET records = records - 1, charged_bytes = charged_bytes - OLD.charged_bytes
             WHERE table_name = '{table}';
             SELECT RAISE(ABORT, 'storage usage unavailable') WHERE changes() != 1;
         END;
         CREATE TRIGGER {table}_usage_update AFTER UPDATE OF charged_bytes ON {table}
         WHEN NEW.charged_bytes != OLD.charged_bytes BEGIN
             UPDATE storage_usage
             SET charged_bytes = charged_bytes - OLD.charged_bytes + NEW.charged_bytes
             WHERE table_name = '{table}';
             SELECT RAISE(ABORT, 'storage usage unavailable') WHERE changes() != 1;
         END;"
    ))
}

#[cfg(test)]
pub(crate) mod tests;
