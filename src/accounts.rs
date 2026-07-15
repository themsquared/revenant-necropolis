//! Human accountability for the network. Reading is open to everyone;
//! PUBLISHING requires a verified human behind the agent. A person registers
//! with an email, verifies it, and binds as many revenant agent identities as
//! they like — but every published artifact traces back to a real, verified
//! human. That's the abuse lever: not gatekeeping consumption, just vouching
//! for who can put things into the horde.
//!
//! Storage is a small SQLite DB (its own connection to the Necropolis file):
//!   accounts(id, email, key_hash, verify_token, verified, created_ts)
//!   agent_bindings(pubkey, account_id, bound_ts)

use anyhow::{bail, Context, Result};
use rusqlite::{Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use std::sync::Mutex;

pub struct Accounts {
    conn: Mutex<Connection>,
}

/// Outcome of a registration — carries the account key (shown once to the
/// caller) and the verify token (emailed to the human, or surfaced in dev).
pub struct Registered {
    pub account_key: String,
    pub verify_token: String,
    pub already: bool,
}

fn rand_hex(n: usize) -> String {
    use rand::RngCore;
    let mut b = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

fn hash(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl Accounts {
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path).with_context(|| format!("opening accounts db {path}"))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS accounts (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                email        TEXT NOT NULL UNIQUE,
                key_hash     TEXT NOT NULL,
                verify_token TEXT,
                verified     INTEGER NOT NULL DEFAULT 0,
                created_ts   INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS agent_bindings (
                pubkey     TEXT PRIMARY KEY,
                account_id INTEGER NOT NULL,
                bound_ts   INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS login_tokens (
                token      TEXT PRIMARY KEY,
                account_id INTEGER NOT NULL,
                created_ts INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS sessions (
                token      TEXT PRIMARY KEY,
                account_id INTEGER NOT NULL,
                created_ts INTEGER NOT NULL
             );",
        )?;
        Ok(Accounts { conn: Mutex::new(conn) })
    }

    /// Register (or re-issue for) an email. Returns the account key (to hold)
    /// and a verify token (to email). Re-registering an unverified email
    /// re-issues a fresh token; a verified email is left alone (`already`).
    pub fn register(&self, email: &str) -> Result<Registered> {
        let email = email.trim().to_lowercase();
        if !email.contains('@') || email.len() < 3 {
            bail!("that doesn't look like an email address");
        }
        let c = self.conn.lock().unwrap();
        let existing: Option<(i64, i64)> = c
            .query_row("SELECT id, verified FROM accounts WHERE email = ?1", [&email], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()?;
        if let Some((_, verified)) = existing {
            if verified == 1 {
                return Ok(Registered {
                    account_key: String::new(),
                    verify_token: String::new(),
                    already: true,
                });
            }
        }
        let account_key = rand_hex(32);
        let token = rand_hex(16);
        c.execute(
            "INSERT INTO accounts (email, key_hash, verify_token, verified, created_ts)
             VALUES (?1, ?2, ?3, 0, ?4)
             ON CONFLICT(email) DO UPDATE SET key_hash = ?2, verify_token = ?3",
            rusqlite::params![email, hash(&account_key), token, now()],
        )?;
        Ok(Registered { account_key, verify_token: token, already: false })
    }

    /// Verify an emailed token → marks the account verified.
    pub fn verify(&self, token: &str) -> Result<bool> {
        let c = self.conn.lock().unwrap();
        let n = c.execute(
            "UPDATE accounts SET verified = 1, verify_token = NULL WHERE verify_token = ?1",
            [token],
        )?;
        Ok(n > 0)
    }

    fn account_id_for_key(&self, c: &Connection, account_key: &str) -> Option<(i64, bool)> {
        c.query_row(
            "SELECT id, verified FROM accounts WHERE key_hash = ?1",
            [hash(account_key)],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)? == 1)),
        )
        .optional()
        .ok()
        .flatten()
    }

    /// Bind an agent pubkey to a verified account. The caller must present the
    /// account key AND a valid signature by the agent over the account key
    /// (proving control of the private key — you can't bind someone else's
    /// identity).
    pub fn bind(&self, account_key: &str, pubkey: &str, sig_hex: &str) -> Result<()> {
        if !revenant_net::identity::verify_hex(pubkey, account_key.as_bytes(), sig_hex) {
            bail!("agent ownership proof failed (signature does not match pubkey)");
        }
        let c = self.conn.lock().unwrap();
        let (account_id, verified) =
            self.account_id_for_key(&c, account_key).context("unknown account key")?;
        if !verified {
            bail!("account not verified yet — check your email and run `revenant net verify <token>`");
        }
        c.execute(
            "INSERT INTO agent_bindings (pubkey, account_id, bound_ts) VALUES (?1, ?2, ?3)
             ON CONFLICT(pubkey) DO UPDATE SET account_id = ?2",
            rusqlite::params![pubkey, account_id, now()],
        )?;
        Ok(())
    }

    /// The agent pubkeys bound to the account holding `account_key` (for the
    /// web dashboard: "your agents"). Empty if the key is unknown.
    pub fn agents_for(&self, account_key: &str) -> Vec<String> {
        let c = self.conn.lock().unwrap();
        let Some((id, _)) = self.account_id_for_key(&c, account_key) else {
            return vec![];
        };
        let mut stmt = match c.prepare("SELECT pubkey FROM agent_bindings WHERE account_id = ?1") {
            Ok(s) => s,
            Err(_) => return vec![],
        };
        stmt.query_map([id], |r| r.get::<_, String>(0))
            .map(|rows| rows.filter_map(|r| r.ok()).collect())
            .unwrap_or_default()
    }

    /// Begin a magic-link login: for a VERIFIED account matching `email`, mint a
    /// one-time login token (15-minute TTL, enforced at redeem). Returns None if
    /// the email is unknown or unverified — the caller must NOT leak which, so it
    /// responds the same either way.
    pub fn request_login(&self, email: &str) -> Result<Option<String>> {
        let email = email.trim().to_lowercase();
        let c = self.conn.lock().unwrap();
        let id: Option<i64> = c
            .query_row("SELECT id FROM accounts WHERE email = ?1 AND verified = 1", [&email], |r| {
                r.get(0)
            })
            .optional()?;
        let Some(id) = id else { return Ok(None) };
        let token = rand_hex(20);
        c.execute(
            "INSERT INTO login_tokens (token, account_id, created_ts) VALUES (?1, ?2, ?3)",
            rusqlite::params![token, id, now()],
        )?;
        Ok(Some(token))
    }

    /// Redeem a login token for a session bearer (7-day TTL). One-time: the login
    /// token is consumed whether or not it was still fresh. Returns None if the
    /// token is unknown or expired.
    pub fn redeem_login(&self, login_token: &str) -> Result<Option<String>> {
        let c = self.conn.lock().unwrap();
        let row: Option<(i64, i64)> = c
            .query_row(
                "SELECT account_id, created_ts FROM login_tokens WHERE token = ?1",
                [login_token],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        c.execute("DELETE FROM login_tokens WHERE token = ?1", [login_token])?; // one-time
        let Some((account_id, created)) = row else { return Ok(None) };
        if now() - created > 900 {
            return Ok(None); // 15-minute login-token TTL
        }
        let session = rand_hex(24);
        c.execute(
            "INSERT INTO sessions (token, account_id, created_ts) VALUES (?1, ?2, ?3)",
            rusqlite::params![session, account_id, now()],
        )?;
        Ok(Some(session))
    }

    /// Bind an agent pubkey to the account behind a login SESSION — the way a
    /// second machine joins an existing account without ever holding the raw
    /// account key. The agent proves control of its key by signing the session
    /// token; the session proves the human is logged in.
    pub fn bind_via_session(&self, session: &str, pubkey: &str, sig_hex: &str) -> Result<()> {
        if !revenant_net::identity::verify_hex(pubkey, session.as_bytes(), sig_hex) {
            bail!("agent ownership proof failed (signature does not match pubkey)");
        }
        let account_id =
            self.account_for_session(session).context("invalid or expired session — log in again")?;
        let c = self.conn.lock().unwrap();
        c.execute(
            "INSERT INTO agent_bindings (pubkey, account_id, bound_ts) VALUES (?1, ?2, ?3)
             ON CONFLICT(pubkey) DO UPDATE SET account_id = ?2",
            rusqlite::params![pubkey, account_id, now()],
        )?;
        Ok(())
    }

    /// Resolve a session bearer to its account id, if the session is valid and
    /// unexpired (7-day TTL).
    pub fn account_for_session(&self, session: &str) -> Option<i64> {
        let c = self.conn.lock().unwrap();
        let row: Option<(i64, i64)> = c
            .query_row(
                "SELECT account_id, created_ts FROM sessions WHERE token = ?1",
                [session],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .ok()
            .flatten();
        let (id, created) = row?;
        if now() - created > 7 * 24 * 3600 {
            return None;
        }
        Some(id)
    }

    /// Agent pubkeys bound to an account id (the session-authenticated form of
    /// `agents_for`, which takes the raw account key).
    pub fn agents_for_id(&self, account_id: i64) -> Vec<String> {
        let c = self.conn.lock().unwrap();
        let mut stmt = match c.prepare("SELECT pubkey FROM agent_bindings WHERE account_id = ?1") {
            Ok(s) => s,
            Err(_) => return vec![],
        };
        stmt.query_map([account_id], |r| r.get::<_, String>(0))
            .map(|rows| rows.filter_map(|r| r.ok()).collect())
            .unwrap_or_default()
    }

    /// The verified account id a pubkey is bound to, if any. Used to collapse
    /// many agent keys down to one human before counting votes — the Sybil
    /// gate. Returns a stable string id (`acct:<n>`); unbound keys have none.
    pub fn account_for(&self, pubkey: &str) -> Option<String> {
        let c = self.conn.lock().unwrap();
        c.query_row(
            "SELECT b.account_id FROM agent_bindings b JOIN accounts a ON a.id = b.account_id
             WHERE b.pubkey = ?1 AND a.verified = 1",
            [pubkey],
            |r| r.get::<_, i64>(0),
        )
        .optional()
        .ok()
        .flatten()
        .map(|id| format!("acct:{id}"))
    }

    /// May this agent publish? True iff its pubkey is bound to a verified account.
    pub fn is_authorized(&self, pubkey: &str) -> bool {
        let c = self.conn.lock().unwrap();
        c.query_row(
            "SELECT a.verified FROM agent_bindings b JOIN accounts a ON a.id = b.account_id
             WHERE b.pubkey = ?1",
            [pubkey],
            |r| r.get::<_, i64>(0),
        )
        .optional()
        .ok()
        .flatten()
        .map(|v| v == 1)
        .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use revenant_net::identity::Identity;

    #[test]
    fn register_verify_bind_authorize_flow() {
        let a = Accounts::open(":memory:").unwrap();
        let id = Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();

        // Unbound agent cannot publish.
        assert!(!a.is_authorized(&id.id()));

        let reg = a.register("dev@example.com").unwrap();
        assert!(!reg.account_key.is_empty() && !reg.verify_token.is_empty());

        // Bind before verify → refused.
        let sig = id.sign_hex(reg.account_key.as_bytes());
        assert!(a.bind(&reg.account_key, &id.id(), &sig).is_err());

        // Verify the email token, then bind.
        assert!(a.verify(&reg.verify_token).unwrap());
        a.bind(&reg.account_key, &id.id(), &sig).unwrap();
        assert!(a.is_authorized(&id.id()));

        // A forged ownership proof (wrong signer) is rejected.
        let other = Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
        let bad = other.sign_hex(reg.account_key.as_bytes());
        assert!(a.bind(&reg.account_key, &id.id(), &bad).is_err());

        // Bad token doesn't verify.
        assert!(!a.verify("deadbeef").unwrap());
    }
}
