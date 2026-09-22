use std::sync::{Arc, Mutex};
use rusqlite::{params, Connection, OptionalExtension};
use thiserror::Error;
use crate::zkp_core_engine::UserPublicKey;

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] rusqlite::Error),
    #[error("Public key decoding error: {0}")]
    DecodingError(String),
}

/// Thread-safe SQLite user public key registry
#[derive(Clone)]
pub struct UserRegistry {
    conn: Arc<Mutex<Connection>>,
}

impl UserRegistry {
    /// Open or create an SQLite database file at `path` (e.g. "zkp_bank.db")
    pub fn open(path: &str) -> Result<Self, StorageError> {
        let conn = Connection::open(path)?;
        Self::init(conn)
    }

    /// Open an in-memory SQLite database (ideal for tests and ephemeral runs)
    pub fn in_memory() -> Result<Self, StorageError> {
        let conn = Connection::open_in_memory()?;
        Self::init(conn)
    }

    fn init(conn: Connection) -> Result<Self, StorageError> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS user_registry (
                user_id TEXT PRIMARY KEY,
                public_key BLOB NOT NULL,
                registered_at INTEGER NOT NULL
            )",
            [],
        )?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Enroll or update a user's public key in the bank's database
    pub fn register(&self, user_id: &str, public_key: &UserPublicKey) -> Result<(), StorageError> {
        let conn = self.conn.lock().unwrap();
        let pk_bytes = public_key.to_bytes();
        let now = chrono::Utc::now().timestamp();

        conn.execute(
            "INSERT INTO user_registry (user_id, public_key, registered_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(user_id) DO UPDATE SET public_key = ?2, registered_at = ?3",
            params![user_id, pk_bytes, now],
        )?;
        Ok(())
    }

    /// Retrieve the registered public key for a user
    pub fn get_public_key(&self, user_id: &str) -> Result<Option<UserPublicKey>, StorageError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT public_key FROM user_registry WHERE user_id = ?1")?;
        let pk_bytes: Option<Vec<u8>> = stmt.query_row(params![user_id], |row| row.get(0)).optional()?;

        match pk_bytes {
            Some(bytes) => {
                let pk = UserPublicKey::from_bytes(&bytes)
                    .map_err(|e| StorageError::DecodingError(format!("{e}")))?;
                Ok(Some(pk))
            }
            None => Ok(None),
        }
    }

    /// Check if a user is registered with the bank
    pub fn is_registered(&self, user_id: &str) -> Result<bool, StorageError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT 1 FROM user_registry WHERE user_id = ?1")?;
        let exists = stmt.exists(params![user_id])?;
        Ok(exists)
    }

    /// Remove a registered user from the database
    pub fn remove(&self, user_id: &str) -> Result<bool, StorageError> {
        let conn = self.conn.lock().unwrap();
        let count = conn.execute("DELETE FROM user_registry WHERE user_id = ?1", params![user_id])?;
        Ok(count > 0)
    }

    /// List all registered user IDs
    pub fn list_users(&self) -> Result<Vec<String>, StorageError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT user_id FROM user_registry ORDER BY user_id ASC")?;
        let users = stmt
            .query_map([], |row| row.get(0))?
            .collect::<Result<Vec<String>, _>>()?;
        Ok(users)
    }

    /// Total count of registered users
    pub fn count(&self) -> Result<usize, StorageError> {
        let conn = self.conn.lock().unwrap();
        let count: usize = conn.query_row("SELECT COUNT(*) FROM user_registry", [], |row| row.get(0))?;
        Ok(count)
    }
}
