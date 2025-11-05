//! Verification history tracking and local database management
//!
//! This module provides functionality for tracking verification jobs in a local
//! SQLite database at `~/.voyager/history.db`. It allows users to:
//! - Track verification progress across sessions
//! - Query past verifications
//! - Re-check verification status
//! - Clean old records

use crate::api::VerifyJobStatus;
use crate::class_hash::ClassHash;
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum HistoryError {
    #[error("[E040] Failed to access history database: {0}\n\nSuggestions:\n  • Check that ~/.voyager directory exists and is writable\n  • Verify disk space is available\n  • Ensure no other process is accessing the database")]
    Database(#[from] rusqlite::Error),

    #[error("[E041] Failed to create history directory: {0}\n\nSuggestions:\n  • Check permissions for home directory\n  • Verify disk space is available\n  • Ensure ~/.voyager directory can be created")]
    Io(#[from] std::io::Error),

    #[error("[E042] Unable to determine home directory\n\nSuggestions:\n  • Check that HOME environment variable is set\n  • Verify user has a valid home directory")]
    NoHomeDir,
}

impl HistoryError {
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::Database(_) => "E040",
            Self::Io(_) => "E041",
            Self::NoHomeDir => "E042",
        }
    }
}

/// A record of a verification job
#[derive(Debug, Clone)]
pub struct VerificationRecord {
    pub id: Option<i64>,
    pub job_id: String,
    pub class_hash: String,
    pub contract_name: String,
    pub network: String,
    pub status: String,
    pub submitted_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub package_name: Option<String>,
    pub scarb_version: String,
    pub cairo_version: String,
    pub dojo_version: Option<String>,
}

impl VerificationRecord {
    /// Create a new verification record
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        job_id: String,
        class_hash: &ClassHash,
        contract_name: String,
        network: String,
        status: VerifyJobStatus,
        package_name: Option<String>,
        scarb_version: String,
        cairo_version: String,
        dojo_version: Option<String>,
    ) -> Self {
        Self {
            id: None,
            job_id,
            class_hash: class_hash.to_string(),
            contract_name,
            network,
            status: status.to_string(),
            submitted_at: Utc::now(),
            completed_at: None,
            package_name,
            scarb_version,
            cairo_version,
            dojo_version,
        }
    }

    /// Update the status of this record
    pub fn update_status(&mut self, status: VerifyJobStatus) {
        self.status = status.to_string();

        // If status is terminal (Success, Fail, CompileFailed), set completed_at
        if matches!(
            status,
            VerifyJobStatus::Success | VerifyJobStatus::Fail | VerifyJobStatus::CompileFailed
        ) {
            self.completed_at = Some(Utc::now());
        }
    }
}

/// History database manager
pub struct HistoryDb {
    conn: Connection,
}

impl HistoryDb {
    /// Get the path to the history database file
    fn get_db_path() -> Result<PathBuf, HistoryError> {
        let home = dirs::home_dir().ok_or(HistoryError::NoHomeDir)?;
        let voyager_dir = home.join(".voyager");

        // Create directory if it doesn't exist
        if !voyager_dir.exists() {
            std::fs::create_dir_all(&voyager_dir)?;
        }

        Ok(voyager_dir.join("history.db"))
    }

    /// Open or create the history database
    pub fn open() -> Result<Self, HistoryError> {
        let db_path = Self::get_db_path()?;
        let conn = Connection::open(db_path)?;

        // Create table if it doesn't exist
        conn.execute(
            "CREATE TABLE IF NOT EXISTS verification_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT NOT NULL UNIQUE,
                class_hash TEXT NOT NULL,
                contract_name TEXT NOT NULL,
                network TEXT NOT NULL,
                status TEXT NOT NULL,
                submitted_at TEXT NOT NULL,
                completed_at TEXT,
                package_name TEXT,
                scarb_version TEXT NOT NULL,
                cairo_version TEXT NOT NULL,
                dojo_version TEXT
            )",
            [],
        )?;

        // Create indices for common queries
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_job_id ON verification_history(job_id)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_class_hash ON verification_history(class_hash)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_network ON verification_history(network)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_status ON verification_history(status)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_submitted_at ON verification_history(submitted_at)",
            [],
        )?;

        Ok(Self { conn })
    }

    /// Insert a new verification record
    pub fn insert(&self, record: &VerificationRecord) -> Result<i64, HistoryError> {
        self.conn.execute(
            "INSERT INTO verification_history
             (job_id, class_hash, contract_name, network, status, submitted_at,
              completed_at, package_name, scarb_version, cairo_version, dojo_version)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                record.job_id,
                record.class_hash,
                record.contract_name,
                record.network,
                record.status,
                record.submitted_at.to_rfc3339(),
                record.completed_at.map(|dt| dt.to_rfc3339()),
                record.package_name,
                record.scarb_version,
                record.cairo_version,
                record.dojo_version,
            ],
        )?;

        Ok(self.conn.last_insert_rowid())
    }

    /// Update the status of a verification record by job ID
    pub fn update_status(
        &self,
        job_id: &str,
        status: &str,
        completed_at: Option<DateTime<Utc>>,
    ) -> Result<(), HistoryError> {
        self.conn.execute(
            "UPDATE verification_history
             SET status = ?1, completed_at = ?2
             WHERE job_id = ?3",
            params![status, completed_at.map(|dt| dt.to_rfc3339()), job_id,],
        )?;
        Ok(())
    }

    /// Get a verification record by job ID
    pub fn get_by_job_id(&self, job_id: &str) -> Result<Option<VerificationRecord>, HistoryError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, job_id, class_hash, contract_name, network, status,
                    submitted_at, completed_at, package_name, scarb_version,
                    cairo_version, dojo_version
             FROM verification_history
             WHERE job_id = ?1",
        )?;

        let record = stmt.query_row(params![job_id], |row| {
            Ok(VerificationRecord {
                id: Some(row.get(0)?),
                job_id: row.get(1)?,
                class_hash: row.get(2)?,
                contract_name: row.get(3)?,
                network: row.get(4)?,
                status: row.get(5)?,
                submitted_at: row
                    .get::<_, String>(6)?
                    .parse()
                    .unwrap_or_else(|_| Utc::now()),
                completed_at: row
                    .get::<_, Option<String>>(7)?
                    .and_then(|s| s.parse().ok()),
                package_name: row.get(8)?,
                scarb_version: row.get(9)?,
                cairo_version: row.get(10)?,
                dojo_version: row.get(11)?,
            })
        });

        match record {
            Ok(rec) => Ok(Some(rec)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// List all verification records, optionally filtered
    pub fn list(
        &self,
        status_filter: Option<&str>,
        network_filter: Option<&str>,
        limit: Option<usize>,
    ) -> Result<Vec<VerificationRecord>, HistoryError> {
        let mut query = String::from(
            "SELECT id, job_id, class_hash, contract_name, network, status,
                    submitted_at, completed_at, package_name, scarb_version,
                    cairo_version, dojo_version
             FROM verification_history WHERE 1=1",
        );

        let mut params: Vec<String> = Vec::new();
        if let Some(s) = status_filter {
            params.push(s.to_string());
            query.push_str(&format!(" AND status = ?{}", params.len()));
        }
        if let Some(n) = network_filter {
            params.push(n.to_string());
            query.push_str(&format!(" AND network = ?{}", params.len()));
        }
        query.push_str(" ORDER BY submitted_at DESC");

        if let Some(lim) = limit {
            query.push_str(&format!(" LIMIT {lim}"));
        }

        let mut stmt = self.conn.prepare(&query)?;

        // Convert params to references
        let param_refs: Vec<&dyn rusqlite::ToSql> =
            params.iter().map(|s| s as &dyn rusqlite::ToSql).collect();

        let records = stmt.query_map(&param_refs[..], |row| {
            Ok(VerificationRecord {
                id: Some(row.get(0)?),
                job_id: row.get(1)?,
                class_hash: row.get(2)?,
                contract_name: row.get(3)?,
                network: row.get(4)?,
                status: row.get(5)?,
                submitted_at: row
                    .get::<_, String>(6)?
                    .parse()
                    .unwrap_or_else(|_| Utc::now()),
                completed_at: row
                    .get::<_, Option<String>>(7)?
                    .and_then(|s| s.parse().ok()),
                package_name: row.get(8)?,
                scarb_version: row.get(9)?,
                cairo_version: row.get(10)?,
                dojo_version: row.get(11)?,
            })
        })?;

        let mut result = Vec::new();
        for record in records {
            result.push(record?);
        }
        Ok(result)
    }

    /// Delete records older than a specified number of days
    pub fn clean_older_than(&self, days: u32) -> Result<usize, HistoryError> {
        let cutoff = Utc::now() - chrono::Duration::days(i64::from(days));
        let cutoff_str = cutoff.to_rfc3339();

        let deleted = self.conn.execute(
            "DELETE FROM verification_history WHERE submitted_at < ?1",
            params![cutoff_str],
        )?;

        Ok(deleted)
    }

    /// Delete all records
    pub fn clean_all(&self) -> Result<usize, HistoryError> {
        let deleted = self.conn.execute("DELETE FROM verification_history", [])?;
        Ok(deleted)
    }

    /// Get statistics about verification history
    pub fn get_stats(&self) -> Result<HistoryStats, HistoryError> {
        let total: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM verification_history", [], |row| {
                    row.get(0)
                })?;

        let successful: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM verification_history WHERE status = 'Success'",
            [],
            |row| row.get(0),
        )?;

        let failed: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM verification_history WHERE status IN ('Fail', 'CompileFailed')",
            [],
            |row| row.get(0),
        )?;

        let pending: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM verification_history WHERE status IN ('Submitted', 'Processing', 'Compiled')",
            [],
            |row| row.get(0),
        )?;

        Ok(HistoryStats {
            total: total as usize,
            successful: successful as usize,
            failed: failed as usize,
            pending: pending as usize,
        })
    }

    /// Calculate average verification time for successful jobs (in seconds)
    ///
    /// Returns the average time from submission to completion for the last N
    /// successful verifications. Returns None if there are fewer than `min_samples`.
    pub fn get_average_verification_time(
        &self,
        samples: usize,
        min_samples: usize,
    ) -> Result<Option<u64>, HistoryError> {
        let mut stmt = self.conn.prepare(
            "SELECT submitted_at, completed_at
             FROM verification_history
             WHERE status = 'Success' AND completed_at IS NOT NULL
             ORDER BY submitted_at DESC
             LIMIT ?1",
        )?;

        let mut durations = Vec::new();

        let rows = stmt.query_map(params![samples], |row| {
            let submitted_str: String = row.get(0)?;
            let completed_str: String = row.get(1)?;

            let submitted: DateTime<Utc> = submitted_str.parse().unwrap_or_else(|_| Utc::now());
            let completed: DateTime<Utc> = completed_str.parse().unwrap_or_else(|_| Utc::now());

            let duration = (completed - submitted).num_seconds();
            Ok(duration.max(0) as u64)
        })?;

        for duration in rows.flatten() {
            durations.push(duration);
        }

        // Need minimum samples for reliable average
        if durations.len() < min_samples {
            return Ok(None);
        }

        let sum: u64 = durations.iter().sum();
        let avg = sum / durations.len() as u64;

        Ok(Some(avg))
    }
}

/// Statistics about verification history
#[derive(Debug, Clone)]
pub struct HistoryStats {
    pub total: usize,
    pub successful: usize,
    pub failed: usize,
    pub pending: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_verification_record() -> Result<(), Box<dyn std::error::Error>> {
        let class_hash = ClassHash::new("0x1234567890abcdef")?;
        let record = VerificationRecord::new(
            "job-123".to_string(),
            &class_hash,
            "TestContract".to_string(),
            "mainnet".to_string(),
            VerifyJobStatus::Submitted,
            Some("test_package".to_string()),
            "2.11.2".to_string(),
            "2.11.4".to_string(),
            None,
        );

        assert_eq!(record.job_id, "job-123");
        assert_eq!(record.contract_name, "TestContract");
        assert_eq!(record.status, "Submitted");
        assert!(record.completed_at.is_none());
        Ok(())
    }

    #[test]
    fn test_update_status() -> Result<(), Box<dyn std::error::Error>> {
        let class_hash = ClassHash::new("0x1234567890abcdef")?;
        let mut record = VerificationRecord::new(
            "job-123".to_string(),
            &class_hash,
            "TestContract".to_string(),
            "mainnet".to_string(),
            VerifyJobStatus::Submitted,
            Some("test_package".to_string()),
            "2.11.2".to_string(),
            "2.11.4".to_string(),
            None,
        );

        assert!(record.completed_at.is_none());

        record.update_status(VerifyJobStatus::Success);
        assert_eq!(record.status, "Success");
        assert!(record.completed_at.is_some());
        Ok(())
    }
}
