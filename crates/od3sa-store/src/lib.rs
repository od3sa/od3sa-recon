//! SQLite storage for od3sa-recon: schema version 1 and the machinery to apply it.
//!
//! # Scope
//!
//! This crate owns the database *schema* and nothing else:
//!
//! * The migrations are **embedded in the binary** with `include_str!`, so the
//!   daemon opens its database without needing any file of its own on disk.
//! * The schema holds **metadata only**. There is no column for a frame
//!   payload or an EAPOL body, and none may be added.
//! * Nothing here touches a radio or the network. The crate is a plain
//!   SQLite wrapper.
//!
//! # Schema version
//!
//! The contract is `docs/SCHEMA.md`. The schema of version 1 lives in
//! `migrations/001_schema_v1.sql` and is the same text, so a schema that
//! drifts from the doc fails the tests in this crate.
//!
//! # Example
//!
//! ```no_run
//! use od3sa_store::Store;
//!
//! let store = Store::open(std::path::Path::new("/tmp/recon.sqlite"))?;
//! for row in store.query("SELECT name FROM devices")?.rows() {
//!     println!("{row:?}");
//! }
//! # Ok::<(), od3sa_store::StoreError>(())
//! ```

#![forbid(unsafe_code)]

mod aggregator;
mod migrator;
mod writer;

#[cfg(test)]
mod aggregation_tests;
#[cfg(test)]
mod tests;

use std::fmt;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, ToSql};

pub use aggregator::{
    AccessPoint, Aggregator, ClientLink, Deauth, Device, LinkLayer, Observation, Probe, Sighting,
};
pub use rusqlite::types::Value;
pub use writer::{AlertRow, Position, Retention, Writer};

/// The schema version this build expects.
///
/// A database written by this build is at this version after
/// [`Store::open`] returns. A database at a *higher* version was written by a
/// newer build and is refused, rather than silently downgraded.
pub const SCHEMA_VERSION: u32 = 1;

/// A database that has had its migrations applied.
///
/// The store owns one SQLite connection. It is opened with
/// `PRAGMA foreign_keys=ON` and, for a file, `PRAGMA journal_mode=WAL`, as
/// `docs/SCHEMA.md` requires.
#[derive(Debug)]
pub struct Store {
    conn: Connection,
    path: Option<PathBuf>,
}

impl Store {
    /// Open (or create) a database at `path` and apply any pending migrations.
    ///
    /// The parent directory must already exist; the store does not create it.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be opened, if the database was
    /// written by a newer build, or if a migration fails. A failed migration
    /// leaves the database at its previous version.
    pub fn open(path: &Path) -> Result<Store, StoreError> {
        let conn = Connection::open(path)?;
        Self::prepare(&conn, true)?;
        Ok(Store {
            conn,
            path: Some(path.to_path_buf()),
        })
    }

    /// Apply pending migrations to an in-memory database. For tests.
    ///
    /// # Errors
    ///
    /// Returns an error if a migration fails. A failed migration leaves the
    /// database at its previous version.
    pub fn open_in_memory() -> Result<Store, StoreError> {
        let conn = Connection::open_in_memory()?;
        Self::prepare(&conn, false)?;
        Ok(Store { conn, path: None })
    }

    /// The path of the database file, when it has one.
    ///
    /// An in-memory database has no path.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// The connection, for the modules of this crate that write to it.
    pub(crate) fn connection(&self) -> &Connection {
        &self.conn
    }

    /// Close the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be closed cleanly.
    pub fn close(self) -> Result<(), StoreError> {
        // `Connection::close` hands the connection back with the error, so
        // that it is dropped cleanly. The error is the interesting part.
        self.conn
            .close()
            .map_err(|(_, error)| StoreError::Sqlite(error))?;
        Ok(())
    }

    /// Open the connection, set the pragmas and apply the migrations.
    fn prepare(conn: &Connection, is_file: bool) -> Result<(), StoreError> {
        // `foreign_keys` is a no-op inside a transaction, so it goes first,
        // before any migration runs.
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        if is_file {
            // WAL is a persistent property of the file, so it only has to be
            // asked for once; asking again is harmless.
            conn.execute_batch("PRAGMA journal_mode = WAL;")?;
        }
        // The page cache is bounded on purpose. SQLite's default is 2 MB per
        // connection, and the daemon holds at least two - the writer's and
        // the query socket's - against a 15 MB RSS budget on a device with
        // about 104 MB free and no swap. A megabyte per connection is enough
        // for a database of sightings.
        conn.execute_batch("PRAGMA cache_size = -1000;")?;
        // No memory-mapped pages: they would count towards the resident
        // set without being the daemon's memory.
        conn.execute_batch("PRAGMA mmap_size = 0;")?;
        migrator::apply(conn, migrator::MIGRATIONS)?;
        Ok(())
    }

    /// The schema version currently in the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the `meta` table is missing or holds a version that
    /// is not a number.
    pub fn schema_version(&self) -> Result<u32, StoreError> {
        migrator::current_version(&self.conn)
    }

    /// Run a query against the database.
    ///
    /// The statement is a single SQL statement. When it returns rows, they
    /// come back in [`Rows`], column names first. When it returns no rows
    /// (an `INSERT`, an `UPDATE`, a `CREATE`), the statement is still
    /// executed, and the returned [`Rows`] is empty.
    ///
    /// A statement that takes values should use [`Store::query_with`], so
    /// that the values are bound and cannot change the meaning of the
    /// statement.
    ///
    /// # Errors
    ///
    /// Returns an error if the statement is not valid SQL, or if it fails -
    /// a foreign key violation, for instance.
    pub fn query(&self, sql: &str) -> Result<Rows, StoreError> {
        self.query_with(sql, &[])
    }

    /// Run a query against the database, with bound parameters.
    ///
    /// The parameters are bound to the `?` placeholders of the statement, in
    /// the order they are given. The caller writes the statement once and
    /// hands the values over separately, so a value cannot change what the
    /// statement means: a quote in a value is a quote in a value.
    ///
    /// The same rules as [`Store::query`]: one statement, and the rows come
    /// back in [`Rows`], column names first.
    ///
    /// # Errors
    ///
    /// Returns an error if the statement is not valid SQL, if the number of
    /// parameters does not match the number of placeholders, or if the
    /// statement fails.
    pub fn query_with(&self, sql: &str, params: &[Value]) -> Result<Rows, StoreError> {
        let bound: Vec<&dyn ToSql> = params.iter().map(|value| value as &dyn ToSql).collect();

        let mut stmt = self.conn.prepare(sql)?;
        let columns: Vec<String> = stmt.column_names().map(str::to_string).collect();

        if columns.is_empty() {
            // A statement without result columns: run it for its effect.
            stmt.execute(bound.as_slice())?;
            return Ok(Rows {
                columns,
                rows: Vec::new(),
            });
        }

        let mut rows = Vec::new();
        let mut result = stmt.query(bound.as_slice())?;
        while let Some(row) = result.next()? {
            let mut values = Vec::with_capacity(columns.len());
            for index in 0..columns.len() {
                values.push(row.get::<_, Value>(index)?);
            }
            rows.push(values);
        }

        Ok(Rows { columns, rows })
    }
}

/// The result of a query: the column names and the rows.
///
/// Each row holds one value per column, in the order of [`Rows::columns`].
/// The values are SQLite's own [`Value`], which maps onto JSON almost one to
/// one: `NULL`, a number, a number, a string, and a blob (which a JSON
/// encoder will want as text).
#[derive(Debug, Clone, PartialEq)]
pub struct Rows {
    columns: Vec<String>,
    rows: Vec<Vec<Value>>,
}

impl Rows {
    /// The column names, in order.
    pub fn columns(&self) -> &[String] {
        &self.columns
    }

    /// The rows, in order.
    pub fn rows(&self) -> &[Vec<Value>] {
        &self.rows
    }

    /// The number of rows.
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether there are no rows.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// One value of one row, by column name.
    ///
    /// Returns `None` if the row is out of range or the column is not in the
    /// result.
    pub fn get(&self, row: usize, column: &str) -> Option<&Value> {
        let index = self.columns.iter().position(|name| name == column)?;
        self.rows.get(row)?.get(index)
    }
}

/// Typed accessors for a SQLite [`Value`].
///
/// SQLite is dynamically typed: a column declared `REAL` can still hold an
/// integer, and a `TEXT` column can hold a blob. These accessors answer
/// "what is in this value, if it is that kind of thing", and return `None`
/// when it is not.
///
/// They are deliberately the same shape as a JSON value, so the query API
/// can turn a row into JSON without a second conversion step.
pub trait ValueExt {
    /// The value as text, if it is text.
    fn as_str(&self) -> Option<&str>;
    /// The value as a signed integer, if it is an integer.
    fn as_integer(&self) -> Option<i64>;
    /// The value as a floating point number, if it is one.
    fn as_real(&self) -> Option<f64>;
    /// The value as bytes, if it is a blob.
    fn as_blob(&self) -> Option<&[u8]>;
}

impl ValueExt for Value {
    fn as_str(&self) -> Option<&str> {
        match self {
            Value::Text(text) => Some(text.as_str()),
            _ => None,
        }
    }

    fn as_integer(&self) -> Option<i64> {
        match self {
            Value::Integer(number) => Some(*number),
            _ => None,
        }
    }

    fn as_real(&self) -> Option<f64> {
        match self {
            Value::Real(number) => Some(*number),
            _ => None,
        }
    }

    fn as_blob(&self) -> Option<&[u8]> {
        match self {
            Value::Blob(bytes) => Some(bytes.as_slice()),
            _ => None,
        }
    }
}

/// Something went wrong while opening or using the database.
#[derive(Debug)]
#[non_exhaustive]
pub enum StoreError {
    /// SQLite reported an error.
    Sqlite(rusqlite::Error),
    /// A migration failed and was rolled back. The database is still at the
    /// version it was at before.
    Migration {
        /// The version the migration would have brought the database to.
        version: u32,
        /// The name of the migration file, without its directory.
        name: &'static str,
        /// The error SQLite reported.
        source: rusqlite::Error,
    },
    /// The database was written by a newer build of the daemon.
    UnsupportedVersion {
        /// The version found in the database.
        found: u32,
        /// The version this build understands.
        supported: u32,
    },
    /// The `meta` table holds no `schema_version` key.
    MissingSchemaVersion,
    /// The `schema_version` in the `meta` table is not a number.
    BadSchemaVersion(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(source) => write!(f, "sqlite error: {source}"),
            Self::Migration {
                version,
                name,
                source,
            } => write!(f, "migration {name} (version {version}) failed: {source}"),
            Self::UnsupportedVersion { found, supported } => write!(
                f,
                "database is at schema version {found}, but this build only understands {supported}"
            ),
            Self::MissingSchemaVersion => write!(f, "the meta table holds no schema_version"),
            Self::BadSchemaVersion(value) => {
                write!(
                    f,
                    "the schema_version in the meta table is not a number: {value}"
                )
            }
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sqlite(source) => Some(source),
            Self::Migration { source, .. } => Some(source),
            Self::UnsupportedVersion { .. }
            | Self::MissingSchemaVersion
            | Self::BadSchemaVersion(_) => None,
        }
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(source: rusqlite::Error) -> Self {
        Self::Sqlite(source)
    }
}
