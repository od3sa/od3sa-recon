//! Applying the schema migrations.
//!
//! The migrations are embedded in the binary with `include_str!`, so the
//! daemon needs no files on disk to open its database.
//!
//! # Rules
//!
//! * Each migration runs in **its own transaction**. The `meta` table's
//!   `schema_version` is bumped in that same transaction, so a database is
//!   never at a version whose schema is only half there.
//! * A migration that fails is rolled back. The database stays at the version
//!   it was at before.
//! * Opening a database that is already at the current version applies
//!   nothing and changes nothing.

use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::Connection;
use rusqlite::OptionalExtension;

use crate::{SCHEMA_VERSION, StoreError};

/// One migration: the version it brings the database to, its name and its SQL.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Migration {
    /// The schema version the database is at once this migration has run.
    pub(crate) version: u32,
    /// The migration's name, without the directory. Used in error messages.
    pub(crate) name: &'static str,
    /// The SQL the migration runs.
    pub(crate) sql: &'static str,
}

/// Every migration this build carries, in version order.
///
/// The SQL lives in `migrations/NNNN_*.sql` and is embedded here, so the
/// daemon ships no migration files.
pub(crate) const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    name: "001_schema_v1",
    sql: include_str!("../migrations/001_schema_v1.sql"),
}];

/// The newest migration must be the version this build claims to write.
/// Adding a migration without bumping `SCHEMA_VERSION` is a mistake, and
/// this makes it a compile error.
const _: () = assert!(
    MIGRATIONS[MIGRATIONS.len() - 1].version == SCHEMA_VERSION,
    "the newest migration and SCHEMA_VERSION disagree"
);

/// Apply every migration the database has not had yet.
///
/// # Errors
///
/// Returns an error if the database was written by a newer build, or if a
/// migration fails. A failed migration is rolled back, so the database is
/// left at its previous version.
pub(crate) fn apply(conn: &Connection, migrations: &[Migration]) -> Result<(), StoreError> {
    let current = current_version(conn)?;

    // The newest migration this build carries. A database past it was
    // written by a newer build, and running it here would be wrong.
    let newest = migrations.iter().map(|m| m.version).max().unwrap_or(0);
    if current > newest {
        return Err(StoreError::UnsupportedVersion {
            found: current,
            supported: newest,
        });
    }

    let mut pending: Vec<&Migration> = migrations
        .iter()
        .filter(|migration| migration.version > current)
        .collect();
    pending.sort_by_key(|migration| migration.version);

    for migration in pending {
        apply_one(conn, migration)?;
    }
    Ok(())
}

/// Run one migration and bump the version, in one transaction.
fn apply_one(conn: &Connection, migration: &Migration) -> Result<(), StoreError> {
    // `unchecked_transaction` takes `&Connection`, which is what the store
    // has. It rolls back when dropped, so an error below leaves the database
    // at its previous version.
    let tx = conn.unchecked_transaction()?;

    tx.execute_batch(migration.sql)
        .map_err(|source| StoreError::Migration {
            version: migration.version,
            name: migration.name,
            source,
        })?;

    // The `meta` table is created by the first migration, so it exists by
    // the time these run - inside the same transaction as the schema.
    tx.execute(
        "INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', ?1)",
        [migration.version.to_string()],
    )
    .map_err(|source| StoreError::Migration {
        version: migration.version,
        name: migration.name,
        source,
    })?;

    // The creation time is written once, by the first migration, and kept
    // afterwards.
    tx.execute(
        "INSERT OR IGNORE INTO meta(key, value) VALUES('created_at', ?1)",
        [created_at_ms().to_string()],
    )
    .map_err(|source| StoreError::Migration {
        version: migration.version,
        name: migration.name,
        source,
    })?;

    tx.commit()?;
    Ok(())
}

/// The schema version currently in the database.
///
/// A database with no `meta` table yet is at version 0: it has had no
/// migration at all.
pub(crate) fn current_version(conn: &Connection) -> Result<u32, StoreError> {
    if !has_meta_table(conn)? {
        return Ok(0);
    }

    let value: Option<String> = conn
        .query_row(
            "SELECT value FROM meta WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .optional()?;

    match value {
        None => Err(StoreError::MissingSchemaVersion),
        Some(value) => value
            .trim()
            .parse::<u32>()
            .map_err(|_| StoreError::BadSchemaVersion(value)),
    }
}

/// Whether the `meta` table is there yet.
fn has_meta_table(conn: &Connection) -> Result<bool, StoreError> {
    let count: i64 = conn.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'meta'",
        [],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

/// The current time in unix epoch milliseconds, as `docs/SCHEMA.md` wants.
fn created_at_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis())
        .unwrap_or(0)
}
