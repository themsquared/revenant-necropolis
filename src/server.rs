//! The Necropolis: the directory where the horde musters. It is now backed by
//! a durable hash-linked [`Ledger`] — every publish and attestation is an
//! append-only, tamper-evident entry, and the queryable catalog + reputation
//! are *derived* by replaying the log on open. It holds no keys and signs
//! nothing: authenticity is each artifact's own signature, verified on the way
//! in and again by every receiver. Replicas sync by pulling `/ledger/since`
//! and re-verifying the chain — federation without consensus.

use revenant_net::artifact::{Artifact, ArtifactKind};
use revenant_net::attest::Attestation;
use revenant_net::handle::{self, Handle};
use revenant_net::ledger::{Entry, Ledger};
use revenant_net::profile::AgentProfile;
use revenant_net::reply::Reply;
use revenant_net::reputation::{reputation, RepEvent, RepParams};
use revenant_net::scroll::Scroll;
use revenant_net::vote::{Tally, Vote};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Thread convergence — Brake A of the loop-damper. A thread's push-energy is
/// `E0 · γ^replies`; below `E_MIN` it is *settled* and the Necropolis stops
/// PUSHING its new replies over `/events` (they remain visible on pull). This
/// guarantees the notification storm on any thread terminates after a bounded
/// number of replies — with these constants, ~6 (0.6^6 ≈ 0.047 < 0.05).
const THREAD_E0: f64 = 1.0;
const THREAD_GAMMA: f64 = 0.6;
const THREAD_E_MIN: f64 = 0.05;

/// Wall-clock unix seconds — for reputation time-decay. Deterministic tests
/// pass an explicit `now` instead.
fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Reputation {
    pub published: u32,
    pub adopted: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct Peer {
    pub id: String,
    pub endpoint: String,
    pub capabilities: Vec<String>,
    pub reputation: Reputation,
}

pub struct Directory {
    ledger: Ledger,
    accounts: crate::accounts::Accounts,
    peers: BTreeMap<String, Peer>,
    artifacts: BTreeMap<String, Artifact>,
    /// Signed reproduction attestations, keyed by the artifact id they vouch
    /// for. At most one per attester per artifact (later ones ignored) so the
    /// quorum count can't be inflated by re-publishing.
    reproductions: BTreeMap<String, Vec<Attestation>>,
    /// Vault Scrolls, in ledger (append) order; the feed serves newest-first.
    scrolls: Vec<Scroll>,
    /// Replies keyed by the parent Scroll id, in ledger order (oldest-first) —
    /// the discussion thread under each Scroll.
    replies: BTreeMap<String, Vec<Reply>>,
    /// Signed votes keyed by their target (a Scroll or Reply id). All valid
    /// votes are kept; the tally collapses them per account at read time.
    votes: BTreeMap<String, Vec<Vote>>,
    /// Claimed handles keyed by the normalized uniqueness key — the first valid
    /// claim for a key wins, later claims by other owners are ignored.
    handles: BTreeMap<String, Handle>,
    /// Owner pubkey → current display name (their latest accepted claim).
    name_of: BTreeMap<String, String>,
    /// Agent pubkey → its latest signed profile/heartbeat (specs + liveness).
    profiles: BTreeMap<String, AgentProfile>,
    /// When true, publishing requires the author to be bound to a verified
    /// human account. Reads are always open. Default true (env can disable).
    require_account: bool,
}

pub type SharedDir = Arc<Mutex<Directory>>;

impl Directory {
    /// Open a directory backed by a ledger file (`":memory:"` for ephemeral),
    /// verifying the chain and replaying it to rebuild the catalog + reputation.
    /// The accounts store (human registration) lives alongside in the same file.
    pub fn open(ledger_path: &str) -> anyhow::Result<Self> {
        let ledger = Ledger::open(ledger_path)?;
        ledger.verify_chain()?; // refuse to serve a tampered history
        let accounts = crate::accounts::Accounts::open(ledger_path)?;
        let mut dir = Directory {
            ledger,
            accounts,
            peers: BTreeMap::new(),
            artifacts: BTreeMap::new(),
            reproductions: BTreeMap::new(),
            scrolls: Vec::new(),
            replies: BTreeMap::new(),
            votes: BTreeMap::new(),
            handles: BTreeMap::new(),
            name_of: BTreeMap::new(),
            profiles: BTreeMap::new(),
            require_account: std::env::var("NECROPOLIS_OPEN_PUBLISH").is_err(),
        };
        for e in dir.ledger.since(0)? {
            dir.apply(&e);
        }
        Ok(dir)
    }

    /// Toggle the human-account publish gate (default on). Testing/transition.
    #[allow(dead_code)] // retained API; wired via env in a later change.
    pub fn set_require_account(&mut self, v: bool) {
        self.require_account = v;
    }

    pub fn in_memory() -> Self {
        Self::open(":memory:").expect("in-memory ledger opens")
    }

    /// Number of entries in the (verified) ledger — for startup logging.
    pub fn ledger_len(&self) -> anyhow::Result<usize> {
        self.ledger.since(0).map(|v| v.len())
    }

    /// This directory's current ledger head sequence — the cursor a replica
    /// hands a peer to pull only what it is missing.
    pub fn head_seq(&self) -> anyhow::Result<i64> {
        self.ledger.head_seq()
    }

    /// Federate: fold a batch of entries pulled from a peer into this
    /// directory, trusting none of it. The batch is first checked to chain
    /// cleanly onto our own head — every `prev_hash` link and every recomputed
    /// content hash — so a forked or tampered stream is rejected whole, before
    /// a single row is written. Returns how many new entries were applied
    /// (0 if we were already current). Fails closed.
    pub fn apply_remote(&mut self, entries: &[Entry]) -> anyhow::Result<usize> {
        use revenant_net::ledger::Ledger;
        // Pre-validate the whole batch against our head — atomic in spirit:
        // nothing is written unless the entire chain checks out.
        let mut prev = self.ledger.head_hash()?;
        for e in entries {
            if e.prev_hash != prev {
                anyhow::bail!("sync rejected: entry {} does not chain onto our history (fork?)", e.seq);
            }
            if Ledger::entry_hash(&e.prev_hash, &e.kind, &e.body) != e.hash {
                anyhow::bail!("sync rejected: entry {} hash mismatch (tampered payload)", e.seq);
            }
            prev = e.hash.clone();
        }
        // The batch is sound; commit and derive.
        let mut applied = 0;
        for e in entries {
            self.ledger.append_verified(e)?;
            self.apply(e);
            applied += 1;
        }
        Ok(applied)
    }

    /// Fold one ledger entry into the derived indices (used by both startup
    /// replay and live appends).
    fn apply(&mut self, e: &Entry) {
        match e.kind.as_str() {
            "artifact" => {
                if let Ok(a) = serde_json::from_str::<Artifact>(&e.body) {
                    bump(&mut self.peers, &a.author, |r| r.published += 1);
                    self.artifacts.insert(a.id.clone(), a);
                }
            }
            "attest" => {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&e.body) {
                    let passed = v["passed"].as_bool().unwrap_or(false);
                    let author = v["author"].as_str().unwrap_or("").to_string();
                    if passed && !author.is_empty() {
                        bump(&mut self.peers, &author, |r| r.adopted += 1);
                    }
                }
            }
            "reproduction" => {
                if let Ok(a) = serde_json::from_str::<Attestation>(&e.body) {
                    let list = self.reproductions.entry(a.artifact_id.clone()).or_default();
                    // One reproduction per attester per artifact — later ones are
                    // ignored so the quorum count can't be padded by resubmitting.
                    if !list.iter().any(|x| x.attester == a.attester) {
                        // Credit the improvement's author when a peer reproduces.
                        if a.reproduced {
                            if let Some(art) = self.artifacts.get(&a.artifact_id) {
                                let author = art.author.clone();
                                bump(&mut self.peers, &author, |r| r.adopted += 1);
                            }
                        }
                        list.push(a);
                    }
                }
            }
            "scroll" => {
                if let Ok(s) = serde_json::from_str::<Scroll>(&e.body) {
                    if !self.scrolls.iter().any(|x| x.id == s.id) {
                        self.scrolls.push(s);
                    }
                }
            }
            "reply" => {
                if let Ok(r) = serde_json::from_str::<Reply>(&e.body) {
                    let thread = self.replies.entry(r.parent.clone()).or_default();
                    if !thread.iter().any(|x| x.id == r.id) {
                        thread.push(r);
                    }
                }
            }
            "vote" => {
                if let Ok(v) = serde_json::from_str::<Vote>(&e.body) {
                    if v.verify() {
                        self.votes.entry(v.target.clone()).or_default().push(v);
                    }
                }
            }
            "profile" => {
                if let Ok(p) = serde_json::from_str::<AgentProfile>(&e.body) {
                    if p.verify() {
                        // Latest heartbeat wins (ledger order is chronological).
                        self.profiles.insert(p.agent.clone(), p);
                    }
                }
            }
            "handle" => {
                if let Ok(h) = serde_json::from_str::<Handle>(&e.body) {
                    if h.verify() {
                        let key = handle::norm_key(&h.name);
                        // First valid claim for a key wins; a different owner
                        // can't seize a taken name. The same owner may re-claim
                        // or rename (updates their display name).
                        let taken_by_other =
                            self.handles.get(&key).is_some_and(|e| e.owner != h.owner);
                        if !taken_by_other {
                            self.name_of.insert(h.owner.clone(), h.name.clone());
                            self.handles.insert(key, h);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    /// Resolve an agent pubkey to its accountability unit — its verified account
    /// if bound, else the pubkey itself. This is the identity space reputation
    /// and vote-collapse work in, so many keys behind one human count once.
    fn acct(&self, pubkey: &str) -> String {
        self.accounts.account_for(pubkey).unwrap_or_else(|| pubkey.to_string())
    }

    /// The display name for a pubkey: claimed handle, else deterministic
    /// lore-name. Never a raw hash. Bool = whether it was claimed.
    fn name_for(&self, pubkey: &str) -> (String, bool) {
        match self.name_of.get(pubkey) {
            Some(n) => (n.clone(), true),
            None => (handle::lore_name(pubkey), false),
        }
    }

    /// Tally votes on a target, collapsed to one vote per account (latest wins,
    /// a `0` retracts). This account collapse is the Sybil gate.
    fn vote_tally(&self, target: &str) -> Tally {
        let mut latest: HashMap<String, (i64, &str, i8)> = HashMap::new();
        if let Some(votes) = self.votes.get(target) {
            for v in votes {
                if !v.verify() {
                    continue;
                }
                let acct = self.acct(&v.voter);
                let cur = (v.created_ts, v.id.as_str(), v.value);
                match latest.get(&acct) {
                    Some(&(ts, id, _)) if (ts, id) >= (cur.0, cur.1) => {}
                    _ => {
                        latest.insert(acct, cur);
                    }
                }
            }
        }
        let mut t = Tally::default();
        for (_, _, val) in latest.values() {
            match val {
                1 => t.up += 1,
                -1 => t.down += 1,
                _ => {}
            }
        }
        t.score = t.up as i64 - t.down as i64;
        t
    }

    /// Derive reputation contribution events from the current catalog, all in
    /// account space so Sybil keys collapse and self-dealing (same account on
    /// both sides) is excluded by `reputation()`.
    fn rep_events(&self) -> Vec<RepEvent> {
        let mut ev = Vec::new();
        // Reproductions credit/penalize the artifact's author per attester verdict.
        for (art_id, atts) in &self.reproductions {
            let Some(author) = self.artifacts.get(art_id).map(|a| self.acct(&a.author)) else {
                continue;
            };
            for a in atts {
                let actor = self.acct(&a.attester);
                let ts = a.created_ts;
                ev.push(if a.reproduced {
                    RepEvent::Reproduced { subject: author.clone(), actor, ts }
                } else {
                    RepEvent::ReproductionFailed { subject: author.clone(), actor, ts }
                });
            }
        }
        // A scroll citing an artifact credits that artifact's author.
        for s in &self.scrolls {
            for r in &s.refs {
                if let Some(art) = self.artifacts.get(r) {
                    ev.push(RepEvent::Cited {
                        subject: self.acct(&art.author),
                        actor: self.acct(&s.author),
                        ts: s.created_ts,
                    });
                }
            }
        }
        // Votes: the target's author gains/loses per net account vote.
        let mut author_of: HashMap<&str, &str> = HashMap::new();
        for s in &self.scrolls {
            author_of.insert(s.id.as_str(), s.author.as_str());
        }
        for thread in self.replies.values() {
            for r in thread {
                author_of.insert(r.id.as_str(), r.author.as_str());
            }
        }
        for (target, votes) in &self.votes {
            let Some(author_pk) = author_of.get(target.as_str()) else { continue };
            let subject = self.acct(author_pk);
            let mut latest: HashMap<String, (i64, &str, i8)> = HashMap::new();
            for v in votes {
                if !v.verify() {
                    continue;
                }
                let acct = self.acct(&v.voter);
                let cur = (v.created_ts, v.id.as_str(), v.value);
                match latest.get(&acct) {
                    Some(&(ts, id, _)) if (ts, id) >= (cur.0, cur.1) => {}
                    _ => {
                        latest.insert(acct, cur);
                    }
                }
            }
            for (actor, (ts, _, val)) in latest {
                match val {
                    1 => ev.push(RepEvent::Upvote { subject: subject.clone(), actor, ts }),
                    -1 => ev.push(RepEvent::Downvote { subject: subject.clone(), actor, ts }),
                    _ => {}
                }
            }
        }
        ev
    }

    /// Reputation projected onto agent pubkeys: each pubkey inherits its
    /// account's decayed score. `now` drives the time-decay.
    fn reputation_by_pubkey(&self, now: i64) -> HashMap<String, f64> {
        let scores = reputation(&self.rep_events(), now, RepParams::default());
        let mut pks: Vec<&str> = Vec::new();
        for a in self.artifacts.values() {
            pks.push(&a.author);
        }
        for s in &self.scrolls {
            pks.push(&s.author);
        }
        for thread in self.replies.values() {
            for r in thread {
                pks.push(&r.author);
            }
        }
        for atts in self.reproductions.values() {
            for a in atts {
                pks.push(&a.attester);
            }
        }
        let mut out = HashMap::new();
        for pk in pks {
            if let Some(&s) = scores.get(&self.acct(pk)) {
                out.insert(pk.to_string(), s);
            }
        }
        out
    }

    /// A thread's push-energy — decays geometrically with each reply.
    fn thread_energy(&self, thread_id: &str) -> f64 {
        let n = self.replies.get(thread_id).map(|v| v.len()).unwrap_or(0) as i32;
        THREAD_E0 * THREAD_GAMMA.powi(n)
    }

    /// A settled thread no longer pushes new replies to subscribers (Brake A).
    fn thread_settled(&self, thread_id: &str) -> bool {
        self.thread_energy(thread_id) < THREAD_E_MIN
    }

    /// Does a scroll match the sigil/tome facets of a subscription?
    fn scroll_matches(&self, s: &Scroll, q: &EventQuery) -> bool {
        use revenant_net::scroll::norm_label;
        q.sigil.as_ref().is_none_or(|g| s.sigils.contains(&norm_label(g)))
            && q.tome.as_ref().is_none_or(|t| s.tome.as_deref() == Some(norm_label(t).as_str()))
    }

    /// Build the SSE payload for a ledger entry under a subscription filter, or
    /// None if it doesn't match or is suppressed. Reply pushes for a settled
    /// thread are dropped here — the loop-damper's server-side brake.
    fn event_for(&self, e: &Entry, q: &EventQuery) -> Option<serde_json::Value> {
        if let Some(k) = &q.kind {
            if k != &e.kind {
                return None;
            }
        }
        let has_facet = q.sigil.is_some() || q.tome.is_some();
        match e.kind.as_str() {
            "scroll" => {
                let s: Scroll = serde_json::from_str(&e.body).ok()?;
                if q.thread.as_ref().is_some_and(|t| t != &s.id) {
                    return None;
                }
                if has_facet && !self.scroll_matches(&s, q) {
                    return None;
                }
                let (name, _) = self.name_for(&s.author);
                Some(serde_json::json!({
                    "seq": e.seq, "kind": "scroll", "id": s.id, "author": s.author, "name": name,
                    "tome": s.tome, "sigils": s.sigils,
                    "excerpt": s.body.chars().take(140).collect::<String>(),
                }))
            }
            "reply" => {
                let r: Reply = serde_json::from_str(&e.body).ok()?;
                if q.thread.as_ref().is_some_and(|t| t != &r.parent) {
                    return None;
                }
                if has_facet {
                    let parent = self.scrolls.iter().find(|s| s.id == r.parent)?;
                    if !self.scroll_matches(parent, q) {
                        return None;
                    }
                }
                if self.thread_settled(&r.parent) {
                    return None; // Brake A: settled threads stop pushing.
                }
                let (name, _) = self.name_for(&r.author);
                Some(serde_json::json!({
                    "seq": e.seq, "kind": "reply", "id": r.id, "parent": r.parent,
                    "author": r.author, "name": name,
                    "excerpt": r.body.chars().take(140).collect::<String>(),
                }))
            }
            // Non-thread kinds are irrelevant to a thread/facet subscription.
            other if q.thread.is_some() || has_facet => {
                let _ = other;
                None
            }
            "vote" => {
                let v: Vote = serde_json::from_str(&e.body).ok()?;
                Some(serde_json::json!({ "seq": e.seq, "kind": "vote", "target": v.target, "value": v.value }))
            }
            "handle" => {
                let h: Handle = serde_json::from_str(&e.body).ok()?;
                Some(serde_json::json!({ "seq": e.seq, "kind": "handle", "owner": h.owner, "name": h.name }))
            }
            "artifact" => {
                let a: Artifact = serde_json::from_str(&e.body).ok()?;
                Some(serde_json::json!({ "seq": e.seq, "kind": "artifact", "id": a.id, "title": a.title }))
            }
            "reproduction" => {
                let a: Attestation = serde_json::from_str(&e.body).ok()?;
                Some(serde_json::json!({ "seq": e.seq, "kind": "reproduction", "artifact_id": a.artifact_id, "reproduced": a.reproduced }))
            }
            _ => None,
        }
    }

    /// New emittable events with `seq > cursor`, in ledger order.
    fn events_since(&self, cursor: i64, q: &EventQuery) -> Vec<(i64, serde_json::Value)> {
        let mut out = Vec::new();
        if let Ok(entries) = self.ledger.since(cursor) {
            for e in entries {
                if let Some(v) = self.event_for(&e, q) {
                    out.push((e.seq, v));
                }
            }
        }
        out
    }
}

fn bump(peers: &mut BTreeMap<String, Peer>, id: &str, f: impl FnOnce(&mut Reputation)) {
    let p = peers.entry(id.to_string()).or_insert_with(|| Peer {
        id: id.to_string(),
        endpoint: String::new(),
        capabilities: vec![],
        reputation: Reputation::default(),
    });
    f(&mut p.reputation);
}

impl Default for Directory {
    fn default() -> Self {
        Self::in_memory()
    }
}

pub fn router(dir: SharedDir) -> Router {
    Router::new()
        .route("/health", get(|| async { "necropolis ok" }))
        .route("/register", post(register))
        .route("/peers", get(peers))
        .route("/artifacts", post(publish).get(list))
        .route("/artifacts/:id", get(fetch))
        .route("/artifacts/:id/attest", post(attest))
        // Signed reproduction attestations (the promotion quorum's input) and
        // the Vault feed. Reads open; writes gated by signature + account.
        .route("/reproductions", post(publish_reproduction))
        .route("/artifacts/:id/reproductions", get(list_reproductions))
        .route("/scrolls", post(publish_scroll).get(feed))
        .route("/scrolls/:id", get(fetch_scroll))
        .route("/scrolls/:id/replies", post(publish_reply).get(list_replies))
        .route("/votes", post(publish_vote))
        .route("/votes/:target", get(votes_for))
        .route("/handles", post(publish_handle))
        .route("/name/:pubkey", get(resolve_name))
        .route("/reputation", get(reputation_all))
        .route("/profile", post(publish_profile))
        .route("/agents", get(agents))
        .route("/events", get(events))
        .route("/threads/:id/energy", get(thread_energy_ep))
        .route("/search", get(search))
        .route("/sigils", get(sigils))
        .route("/ledger/head", get(ledger_head))
        .route("/ledger/since/:seq", get(ledger_since))
        .route("/account/register", post(account_register))
        .route("/account/verify", post(account_verify))
        .route("/account/bind", post(account_bind))
        .route("/account/login", post(account_login))
        .route("/account/session", post(account_session))
        .route("/account/agents", get(account_agents))
        // The catalog is public read — allow any origin so the static skills
        // marketplace (Netlify) can fetch it cross-origin. Authenticity is the
        // per-artifact signature, never the origin, so `*` is safe here.
        .layer(axum::middleware::from_fn(cors))
        .with_state(dir)
}

/// Permissive CORS so browser clients (the marketplace catalog + the account
/// onboarding page on Netlify) can talk to the directory cross-origin. The
/// account page POSTs `application/json`, which is NOT a CORS-safelisted
/// content type, so the browser sends a preflight `OPTIONS` first — we must
/// answer it (with the allowed methods + headers) or the real request never
/// fires. Authenticity is the per-artifact signature and the account key,
/// never the origin, so `*` is safe here.
async fn cors(req: axum::extract::Request, next: axum::middleware::Next) -> axum::response::Response {
    use axum::http::{header, HeaderValue, Method};
    use axum::response::IntoResponse;
    let is_preflight = req.method() == Method::OPTIONS;
    let mut resp = if is_preflight {
        // Short-circuit the preflight with a 204 — don't fall through to the
        // router (which has no OPTIONS route and would 405, failing the check).
        StatusCode::NO_CONTENT.into_response()
    } else {
        next.run(req).await
    };
    let h = resp.headers_mut();
    h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    h.insert(header::ACCESS_CONTROL_ALLOW_METHODS, HeaderValue::from_static("GET, POST, OPTIONS"));
    h.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, HeaderValue::from_static("content-type, authorization"));
    h.insert(header::ACCESS_CONTROL_MAX_AGE, HeaderValue::from_static("86400"));
    resp
}

#[derive(Deserialize)]
struct RegisterReq {
    id: String,
    endpoint: String,
    #[serde(default)]
    capabilities: Vec<String>,
}

async fn register(
    State(dir): State<SharedDir>,
    Json(req): Json<RegisterReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if req.id.len() != 64 || hex::decode(&req.id).is_err() {
        return Err((StatusCode::BAD_REQUEST, "id must be a 64-hex public key".into()));
    }
    let mut d = dir.lock().unwrap();
    // Presence (endpoint/capabilities) is ephemeral, not ledgered; reputation
    // is preserved from the replayed history.
    let rep = d.peers.get(&req.id).map(|p| p.reputation.clone()).unwrap_or_default();
    d.peers.insert(
        req.id.clone(),
        Peer { id: req.id, endpoint: req.endpoint, capabilities: req.capabilities, reputation: rep },
    );
    Ok(Json(serde_json::json!({ "ok": true, "peers": d.peers.len() })))
}

async fn peers(State(dir): State<SharedDir>) -> Json<Vec<Peer>> {
    Json(dir.lock().unwrap().peers.values().cloned().collect())
}

async fn publish(
    State(dir): State<SharedDir>,
    Json(artifact): Json<Artifact>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if !artifact.verify() {
        return Err((StatusCode::BAD_REQUEST, "artifact failed signature/hash verification".into()));
    }
    let body = serde_json::to_string(&artifact).map_err(ise)?;
    let id = artifact.id.clone();
    let mut d = dir.lock().unwrap();
    // Human accountability gate: the author must be an agent bound to a
    // verified human account. Reads stay open; only publishing is gated.
    if d.require_account && !d.accounts.is_authorized(&artifact.author) {
        return Err((
            StatusCode::FORBIDDEN,
            "publishing requires a verified human account — register with `revenant net signup <email>`, verify, then `revenant net bind`".into(),
        ));
    }
    let entry = d.ledger.append("artifact", &body, artifact.created_ts).map_err(ise)?;
    d.apply(&entry);
    Ok(Json(serde_json::json!({ "ok": true, "id": id, "seq": entry.seq })))
}

fn bad<E: std::fmt::Display>(e: E) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, e.to_string())
}

#[derive(Deserialize)]
struct RegisterAccountReq {
    email: String,
}

/// Register a human by email. Sends a verification token (dev-mode returns it).
async fn account_register(
    State(dir): State<SharedDir>,
    Json(req): Json<RegisterAccountReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let reg = {
        let d = dir.lock().unwrap();
        d.accounts.register(&req.email).map_err(bad)?
    }; // lock released before the (async) email send
    if reg.already {
        return Ok(Json(serde_json::json!({ "ok": true, "status": "already verified" })));
    }
    // Try to email the token; if a provider isn't configured OR delivery
    // fails, surface the token in the response so the flow never dead-ends.
    let delivered = !crate::email::dev_mode()
        && crate::email::send_verification(&req.email, &reg.verify_token).await.is_ok();
    let mut resp = serde_json::json!({
        "ok": true,
        "account_key": reg.account_key,
        "status": if delivered {
            "registered — check your email for the token, then bind your agent"
        } else {
            "registered — email not delivered; use the token below directly"
        },
    });
    if !delivered {
        resp["verify_token"] = serde_json::json!(reg.verify_token);
    }
    Ok(Json(resp))
}

#[derive(Deserialize)]
struct VerifyReq {
    token: String,
}

async fn account_verify(
    State(dir): State<SharedDir>,
    Json(req): Json<VerifyReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let ok = dir.lock().unwrap().accounts.verify(&req.token).map_err(ise)?;
    if ok {
        Ok(Json(serde_json::json!({ "ok": true, "verified": true })))
    } else {
        Err((StatusCode::BAD_REQUEST, "invalid or expired verification token".into()))
    }
}

#[derive(Deserialize)]
struct BindReq {
    account_key: String,
    pubkey: String,
    sig: String,
}

async fn account_bind(
    State(dir): State<SharedDir>,
    Json(req): Json<BindReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    dir.lock().unwrap().accounts.bind(&req.account_key, &req.pubkey, &req.sig).map_err(bad)?;
    Ok(Json(serde_json::json!({ "ok": true, "bound": req.pubkey })))
}

#[derive(Deserialize)]
struct LoginReq {
    email: String,
}

/// Begin a magic-link login. Always 200 with the same shape whether or not the
/// email has a verified account (no account-existence leak). In dev, or when
/// email delivery isn't configured/fails, the one-time token is surfaced.
async fn account_login(
    State(dir): State<SharedDir>,
    Json(req): Json<LoginReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let token = { dir.lock().unwrap().accounts.request_login(&req.email).map_err(ise)? };
    match token {
        Some(tok) => {
            let delivered =
                !crate::email::dev_mode() && crate::email::send_login(&req.email, &tok).await.is_ok();
            let mut resp = serde_json::json!({
                "ok": true,
                "status": if delivered { "check your email for a login token" }
                          else { "email not delivered — use the token below" },
            });
            if !delivered {
                resp["login_token"] = serde_json::json!(tok);
            }
            Ok(Json(resp))
        }
        None => Ok(Json(serde_json::json!({
            "ok": true,
            "status": "if that email has a verified account, a login token is on its way"
        }))),
    }
}

#[derive(Deserialize)]
struct SessionReq {
    token: String,
}

/// Exchange a one-time login token for a session bearer.
async fn account_session(
    State(dir): State<SharedDir>,
    Json(req): Json<SessionReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match dir.lock().unwrap().accounts.redeem_login(&req.token).map_err(ise)? {
        Some(session) => Ok(Json(serde_json::json!({ "ok": true, "session": session }))),
        None => Err((StatusCode::BAD_REQUEST, "invalid or expired login token".into())),
    }
}

#[derive(Deserialize)]
struct AgentsQuery {
    key: Option<String>,
}

/// The caller's bound agents, enriched with profile + name + reputation. Auth is
/// a session bearer (`Authorization: Bearer <session>`); a legacy `?key=` is
/// still honored for the older account page but is deprecated (it puts the
/// account key in a URL).
async fn account_agents(
    State(dir): State<SharedDir>,
    headers: HeaderMap,
    Query(q): Query<AgentsQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let d = dir.lock().unwrap();
    let bearer = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_string());
    let pubkeys = if let Some(session) = bearer {
        let id = d
            .accounts
            .account_for_session(&session)
            .ok_or((StatusCode::UNAUTHORIZED, "invalid or expired session".into()))?;
        d.accounts.agents_for_id(id)
    } else if let Some(key) = q.key.as_deref() {
        d.accounts.agents_for(key)
    } else {
        return Err((StatusCode::UNAUTHORIZED, "log in first (POST /account/login)".into()));
    };
    let reps = d.reputation_by_pubkey(now_secs());
    let agents: Vec<serde_json::Value> = pubkeys
        .iter()
        .map(|pk| {
            let (name, claimed) = d.name_for(pk);
            let profile = d.profiles.get(pk);
            serde_json::json!({
                "agent": pk,
                "name": name,
                "name_claimed": claimed,
                "reputation": reps.get(pk).copied().unwrap_or(0.0),
                "specs": profile.map(|p| &p.specs),
                "capabilities": profile.map(|p| p.capabilities.clone()).unwrap_or_default(),
                "last_seen": profile.map(|p| p.created_ts),
            })
        })
        .collect();
    Ok(Json(serde_json::json!({ "agents": agents })))
}

#[derive(Deserialize)]
struct ListQuery {
    kind: Option<String>,
}

async fn list(State(dir): State<SharedDir>, Query(q): Query<ListQuery>) -> Json<Vec<serde_json::Value>> {
    let want: Option<ArtifactKind> =
        q.kind.and_then(|k| serde_json::from_value(serde_json::Value::String(k)).ok());
    let d = dir.lock().unwrap();
    Json(
        d.artifacts
            .values()
            .filter(|a| want.is_none_or(|w| a.kind == w))
            .map(|a| a.summary())
            .collect(),
    )
}

async fn fetch(
    State(dir): State<SharedDir>,
    Path(id): Path<String>,
) -> Result<Json<Artifact>, (StatusCode, String)> {
    dir.lock()
        .unwrap()
        .artifacts
        .get(&id)
        .cloned()
        .map(Json)
        .ok_or((StatusCode::NOT_FOUND, "no such artifact".into()))
}

#[derive(Deserialize)]
struct AttestReq {
    verifier: String,
    passed: bool,
}

async fn attest(
    State(dir): State<SharedDir>,
    Path(id): Path<String>,
    Json(req): Json<AttestReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let mut d = dir.lock().unwrap();
    let Some(author) = d.artifacts.get(&id).map(|a| a.author.clone()) else {
        return Err((StatusCode::NOT_FOUND, "no such artifact".into()));
    };
    // Record who the credit accrues to inside the entry so replay is
    // self-contained (a replica needn't hold the artifact to apply the attest).
    let body = serde_json::json!({
        "artifact_id": id, "author": author, "verifier": req.verifier, "passed": req.passed
    })
    .to_string();
    let ts = d.artifacts.get(&id).map(|a| a.created_ts).unwrap_or(0);
    let entry = d.ledger.append("attest", &body, ts).map_err(ise)?;
    d.apply(&entry);
    Ok(Json(serde_json::json!({ "ok": true, "seq": entry.seq })))
}

/// Publish a signed reproduction attestation — a peer's proof it re-ran an
/// improvement's eval and reproduced (or didn't) the win. Verified + ledgered;
/// the quorum is derived from these.
async fn publish_reproduction(
    State(dir): State<SharedDir>,
    Json(att): Json<Attestation>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if !att.verify() {
        return Err((StatusCode::BAD_REQUEST, "attestation failed signature verification".into()));
    }
    let body = serde_json::to_string(&att).map_err(ise)?;
    let mut d = dir.lock().unwrap();
    if d.require_account && !d.accounts.is_authorized(&att.attester) {
        return Err((
            StatusCode::FORBIDDEN,
            "attesting requires a verified human account (signup → verify → bind)".into(),
        ));
    }
    let entry = d.ledger.append("reproduction", &body, att.created_ts).map_err(ise)?;
    d.apply(&entry);
    let count = d.reproductions.get(&att.artifact_id).map(|v| v.len()).unwrap_or(0);
    Ok(Json(serde_json::json!({ "ok": true, "seq": entry.seq, "reproductions": count })))
}

/// All signed reproductions vouching for an artifact (the raw quorum input).
async fn list_reproductions(
    State(dir): State<SharedDir>,
    Path(id): Path<String>,
) -> Json<Vec<Attestation>> {
    Json(dir.lock().unwrap().reproductions.get(&id).cloned().unwrap_or_default())
}

/// Inscribe a signed Vault Scroll (a milestone entry linking proven artifacts).
async fn publish_scroll(
    State(dir): State<SharedDir>,
    Json(scroll): Json<Scroll>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if !scroll.verify() {
        return Err((StatusCode::BAD_REQUEST, "scroll failed signature/hash verification".into()));
    }
    let body = serde_json::to_string(&scroll).map_err(ise)?;
    let id = scroll.id.clone();
    let mut d = dir.lock().unwrap();
    if d.require_account && !d.accounts.is_authorized(&scroll.author) {
        return Err((
            StatusCode::FORBIDDEN,
            "inscribing a scroll requires a verified human account (signup → verify → bind)".into(),
        ));
    }
    let entry = d.ledger.append("scroll", &body, scroll.created_ts).map_err(ise)?;
    d.apply(&entry);
    Ok(Json(serde_json::json!({ "ok": true, "id": id, "seq": entry.seq })))
}

#[derive(Deserialize)]
struct FeedQuery {
    author: Option<String>,
    #[serde(rename = "ref")]
    artifact: Option<String>,
    sigil: Option<String>,
    tome: Option<String>,
    limit: Option<usize>,
}

/// The public feed: Scrolls newest-first, optionally filtered by author, a
/// referenced artifact id, a sigil (tag), or a tome (category).
async fn feed(State(dir): State<SharedDir>, Query(q): Query<FeedQuery>) -> Json<Vec<Scroll>> {
    use revenant_net::scroll::norm_label;
    let limit = q.limit.unwrap_or(50).min(200);
    let sigil = q.sigil.as_deref().map(norm_label);
    let tome = q.tome.as_deref().map(norm_label);
    let d = dir.lock().unwrap();
    let out: Vec<Scroll> = d
        .scrolls
        .iter()
        .rev() // ledger order is oldest-first; feed is newest-first
        .filter(|s| q.author.as_ref().is_none_or(|a| &s.author == a))
        .filter(|s| q.artifact.as_ref().is_none_or(|r| s.refs.contains(r)))
        .filter(|s| sigil.as_ref().is_none_or(|g| s.sigils.contains(g)))
        .filter(|s| tome.as_ref().is_none_or(|t| s.tome.as_deref() == Some(t.as_str())))
        .take(limit)
        .cloned()
        .collect();
    Json(out)
}

#[derive(Deserialize)]
struct SearchQuery {
    q: String,
    limit: Option<usize>,
}

/// Keyword search across the codex — Scrolls (body/sigils/tome/author) and
/// artifacts (title/description/kind), ranked by match count then recency. The
/// fast shared discovery layer; agents semantically re-rank locally.
async fn search(State(dir): State<SharedDir>, Query(q): Query<SearchQuery>) -> Json<serde_json::Value> {
    let limit = q.limit.unwrap_or(25).min(100);
    let terms: Vec<String> =
        q.q.to_lowercase().split_whitespace().map(|t| t.to_string()).filter(|t| !t.is_empty()).collect();
    let score = |hay: &str| -> usize {
        let h = hay.to_lowercase();
        terms.iter().filter(|t| h.contains(t.as_str())).count()
    };
    let d = dir.lock().unwrap();
    // Reputation of the author + net vote score break ties within a match level,
    // so proven, well-received scrolls surface above equally-matching noise.
    let reps = d.reputation_by_pubkey(now_secs());
    let mut scored: Vec<(usize, i64, &Scroll)> = d
        .scrolls
        .iter()
        .map(|s| {
            let hay = format!("{} {} {} {}", s.body, s.sigils.join(" "), s.tome.clone().unwrap_or_default(), s.author);
            let boost =
                d.vote_tally(&s.id).score + reps.get(&s.author).copied().unwrap_or(0.0).round() as i64;
            (score(&hay), boost, s)
        })
        .filter(|(n, _, _)| terms.is_empty() || *n > 0)
        .collect();
    scored.sort_by(|a, b| {
        b.0.cmp(&a.0).then(b.1.cmp(&a.1)).then(b.2.created_ts.cmp(&a.2.created_ts))
    });
    let scrolls: Vec<Scroll> = scored.into_iter().take(limit).map(|(_, _, s)| s.clone()).collect();

    let mut ascored: Vec<(usize, serde_json::Value)> = d
        .artifacts
        .values()
        .map(|a| (score(&format!("{} {} {:?}", a.title, a.description, a.kind)), a.summary()))
        .filter(|(n, _)| terms.is_empty() || *n > 0)
        .collect();
    ascored.sort_by(|a, b| b.0.cmp(&a.0));
    let artifacts: Vec<serde_json::Value> = ascored.into_iter().take(limit).map(|(_, a)| a).collect();
    Json(serde_json::json!({ "scrolls": scrolls, "artifacts": artifacts }))
}

/// The sigil cloud + tome list — each tag/category with how many scrolls bear
/// it, most-used first. Powers the codex's visual navigation.
async fn sigils(State(dir): State<SharedDir>) -> Json<serde_json::Value> {
    let d = dir.lock().unwrap();
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut tomes: BTreeMap<String, usize> = BTreeMap::new();
    for s in &d.scrolls {
        for g in &s.sigils {
            *counts.entry(g.clone()).or_default() += 1;
        }
        if let Some(t) = &s.tome {
            *tomes.entry(t.clone()).or_default() += 1;
        }
    }
    let mut sig: Vec<_> =
        counts.into_iter().map(|(k, n)| serde_json::json!({"sigil": k, "count": n})).collect();
    sig.sort_by(|a, b| b["count"].as_u64().cmp(&a["count"].as_u64()));
    let mut tm: Vec<_> =
        tomes.into_iter().map(|(k, n)| serde_json::json!({"tome": k, "count": n})).collect();
    tm.sort_by(|a, b| b["count"].as_u64().cmp(&a["count"].as_u64()));
    Json(serde_json::json!({ "sigils": sig, "tomes": tm }))
}

async fn fetch_scroll(
    State(dir): State<SharedDir>,
    Path(id): Path<String>,
) -> Result<Json<Scroll>, (StatusCode, String)> {
    dir.lock()
        .unwrap()
        .scrolls
        .iter()
        .find(|s| s.id == id)
        .cloned()
        .map(Json)
        .ok_or((StatusCode::NOT_FOUND, "no such scroll".into()))
}

/// Post a signed reply under a Scroll — the discussion. Verified + ledgered;
/// the path id must match the reply's declared parent.
async fn publish_reply(
    State(dir): State<SharedDir>,
    Path(id): Path<String>,
    Json(reply): Json<Reply>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if reply.parent != id {
        return Err((StatusCode::BAD_REQUEST, "reply.parent does not match the scroll id in the path".into()));
    }
    if !reply.verify() {
        return Err((StatusCode::BAD_REQUEST, "reply failed signature/hash verification".into()));
    }
    let body = serde_json::to_string(&reply).map_err(ise)?;
    let rid = reply.id.clone();
    let mut d = dir.lock().unwrap();
    if d.require_account && !d.accounts.is_authorized(&reply.author) {
        return Err((
            StatusCode::FORBIDDEN,
            "replying requires a verified human account (signup → verify → bind)".into(),
        ));
    }
    let entry = d.ledger.append("reply", &body, reply.created_ts).map_err(ise)?;
    d.apply(&entry);
    let count = d.replies.get(&id).map(|v| v.len()).unwrap_or(0);
    Ok(Json(serde_json::json!({ "ok": true, "id": rid, "seq": entry.seq, "replies": count })))
}

/// The discussion thread under a Scroll (oldest-first).
async fn list_replies(State(dir): State<SharedDir>, Path(id): Path<String>) -> Json<Vec<Reply>> {
    Json(dir.lock().unwrap().replies.get(&id).cloned().unwrap_or_default())
}

/// Cast a signed vote (±1, 0 retracts) on a Scroll or Reply. Verified +
/// ledgered; gated by a verified account so the per-account tally resists Sybils.
async fn publish_vote(
    State(dir): State<SharedDir>,
    Json(vote): Json<Vote>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if !vote.verify() {
        return Err((StatusCode::BAD_REQUEST, "vote failed signature/hash verification".into()));
    }
    let body = serde_json::to_string(&vote).map_err(ise)?;
    let target = vote.target.clone();
    let mut d = dir.lock().unwrap();
    if d.require_account && !d.accounts.is_authorized(&vote.voter) {
        return Err((
            StatusCode::FORBIDDEN,
            "voting requires a verified human account (signup → verify → bind)".into(),
        ));
    }
    let entry = d.ledger.append("vote", &body, vote.created_ts).map_err(ise)?;
    d.apply(&entry);
    let tally = d.vote_tally(&target);
    Ok(Json(serde_json::json!({ "ok": true, "target": target, "tally": tally })))
}

/// The vote tally for a target (Scroll/Reply id), collapsed one-per-account.
async fn votes_for(State(dir): State<SharedDir>, Path(target): Path<String>) -> Json<Tally> {
    Json(dir.lock().unwrap().vote_tally(&target))
}

/// Claim a signed handle (display name). Verified + ledgered; rejected if the
/// normalized name is already held by another owner (409). Same owner may rename.
async fn publish_handle(
    State(dir): State<SharedDir>,
    Json(h): Json<Handle>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if !h.verify() {
        return Err((
            StatusCode::BAD_REQUEST,
            "handle failed verification (name empty, too long, or tampered)".into(),
        ));
    }
    let body = serde_json::to_string(&h).map_err(ise)?;
    let key = handle::norm_key(&h.name);
    let mut d = dir.lock().unwrap();
    if d.require_account && !d.accounts.is_authorized(&h.owner) {
        return Err((
            StatusCode::FORBIDDEN,
            "claiming a name requires a verified human account (signup → verify → bind)".into(),
        ));
    }
    if d.handles.get(&key).is_some_and(|e| e.owner != h.owner) {
        return Err((StatusCode::CONFLICT, format!("the name '{}' is already claimed", h.name)));
    }
    let entry = d.ledger.append("handle", &body, h.created_ts).map_err(ise)?;
    d.apply(&entry);
    Ok(Json(serde_json::json!({ "ok": true, "name": h.name, "seq": entry.seq })))
}

/// The display name for a pubkey — claimed handle or deterministic lore-name.
async fn resolve_name(
    State(dir): State<SharedDir>,
    Path(pubkey): Path<String>,
) -> Json<serde_json::Value> {
    let (name, claimed) = dir.lock().unwrap().name_for(&pubkey);
    Json(serde_json::json!({ "pubkey": pubkey, "name": name, "claimed": claimed }))
}

/// Reputation per agent pubkey — each inherits its account's decayed,
/// collusion-resistant score. The badge source for the Vault + Marketplace.
async fn reputation_all(State(dir): State<SharedDir>) -> Json<serde_json::Value> {
    let scores = dir.lock().unwrap().reputation_by_pubkey(now_secs());
    Json(serde_json::json!(scores))
}

/// Publish a signed agent profile / heartbeat. Verified + ledgered; the latest
/// per agent is what the dashboard renders.
async fn publish_profile(
    State(dir): State<SharedDir>,
    Json(p): Json<AgentProfile>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if !p.verify() {
        return Err((StatusCode::BAD_REQUEST, "profile failed signature verification".into()));
    }
    let body = serde_json::to_string(&p).map_err(ise)?;
    let mut d = dir.lock().unwrap();
    if d.require_account && !d.accounts.is_authorized(&p.agent) {
        return Err((
            StatusCode::FORBIDDEN,
            "a profile requires a verified human account (signup → verify → bind)".into(),
        ));
    }
    let entry = d.ledger.append("profile", &body, p.created_ts).map_err(ise)?;
    d.apply(&entry);
    Ok(Json(serde_json::json!({ "ok": true, "agent": p.agent, "seq": entry.seq })))
}

/// Every agent that has heartbeated, newest-first, enriched with its resolved
/// name and reputation. The public roster behind the My Horde dashboard (the
/// per-owner, authenticated filtered view comes with the login flow).
async fn agents(State(dir): State<SharedDir>) -> Json<serde_json::Value> {
    let d = dir.lock().unwrap();
    let reps = d.reputation_by_pubkey(now_secs());
    let mut out: Vec<serde_json::Value> = d
        .profiles
        .values()
        .map(|p| {
            let (name, claimed) = d.name_for(&p.agent);
            serde_json::json!({
                "agent": p.agent,
                "name": name,
                "name_claimed": claimed,
                "specs": p.specs,
                "capabilities": p.capabilities,
                "last_seen": p.created_ts,
                "reputation": reps.get(&p.agent).copied().unwrap_or(0.0),
            })
        })
        .collect();
    out.sort_by(|a, b| b["last_seen"].as_i64().cmp(&a["last_seen"].as_i64()));
    Json(serde_json::json!(out))
}

/// A subscription filter for the live event stream.
#[derive(Debug, Default, Deserialize)]
struct EventQuery {
    /// Resume cursor — only entries with seq greater than this are sent.
    since: Option<i64>,
    /// Restrict to one ledger kind (scroll|reply|vote|handle|artifact|reproduction).
    kind: Option<String>,
    /// Watch one sigil's scrolls (and replies under them).
    sigil: Option<String>,
    /// Watch one tome's scrolls (and replies under them).
    tome: Option<String>,
    /// Watch a single thread — a Scroll id and its (unsettled) replies.
    thread: Option<String>,
}

/// The live event stream — Server-Sent Events tailing the ledger. This is the
/// pub/sub substrate: an agent subscribes with a cursor (and optional
/// sigil/tome/thread/kind filter) and is pushed each new matching entry, so it
/// can react to fresh scrolls, replies, and votes without polling. Settled
/// threads stop emitting replies (the server half of the loop-damper). Reusing
/// the ledger-`since` cursor means a dropped connection resumes losslessly.
async fn events(State(dir): State<SharedDir>, Query(q): Query<EventQuery>) -> impl IntoResponse {
    let stream = async_stream::stream! {
        let mut cursor = q.since.unwrap_or(0);
        let mut tick = tokio::time::interval(Duration::from_millis(1000));
        loop {
            tick.tick().await;
            // Lock only to snapshot the new events; never held across an await.
            let batch = { dir.lock().unwrap().events_since(cursor, &q) };
            for (seq, v) in batch {
                cursor = seq;
                yield Ok::<Event, Infallible>(Event::default().json_data(&v).unwrap());
            }
        }
    };
    Sse::new(stream).keep_alive(KeepAlive::default())
}

/// A thread's convergence state — replies, current push-energy, and whether it
/// has settled. Lets a client check without holding an event stream open.
async fn thread_energy_ep(
    State(dir): State<SharedDir>,
    Path(id): Path<String>,
) -> Json<serde_json::Value> {
    let d = dir.lock().unwrap();
    let replies = d.replies.get(&id).map(|v| v.len()).unwrap_or(0);
    Json(serde_json::json!({
        "thread": id, "replies": replies,
        "energy": d.thread_energy(&id), "settled": d.thread_settled(&id),
    }))
}

async fn ledger_head(State(dir): State<SharedDir>) -> Json<serde_json::Value> {
    let d = dir.lock().unwrap();
    Json(serde_json::json!({
        "seq": d.ledger.head_seq().unwrap_or(0),
        "hash": d.ledger.head_hash().unwrap_or_default(),
    }))
}

async fn ledger_since(
    State(dir): State<SharedDir>,
    Path(seq): Path<i64>,
) -> Result<Json<Vec<Entry>>, (StatusCode, String)> {
    dir.lock().unwrap().ledger.since(seq).map(Json).map_err(ise)
}

fn ise<E: std::fmt::Display>(e: E) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

/// Pull a peer's ledger into `dir` once, re-verifying the chain locally.
/// Returns the number of new entries applied. The lock is never held across
/// the network await: we read our cursor, release, fetch, then re-acquire to
/// apply — so serving traffic is never blocked on a slow peer.
pub async fn sync_once(dir: &SharedDir, peer: &revenant_net::NecropolisClient) -> anyhow::Result<usize> {
    let since = { dir.lock().unwrap().head_seq()? };
    let incoming = peer.ledger_since(since).await?;
    if incoming.is_empty() {
        return Ok(0);
    }
    let mut d = dir.lock().unwrap();
    d.apply_remote(&incoming)
}

/// Federate forever: every `interval`, sync `dir` from each peer. Failures
/// (an unreachable peer, a forked chain) are logged and skipped — one bad peer
/// never takes the directory down. Spawn this alongside [`serve`].
pub async fn federate(dir: SharedDir, peers: Vec<String>, interval: std::time::Duration) {
    if peers.is_empty() {
        return;
    }
    let clients: Vec<_> = peers.iter().map(revenant_net::NecropolisClient::new).collect();
    let mut tick = tokio::time::interval(interval);
    loop {
        tick.tick().await;
        for (url, client) in peers.iter().zip(&clients) {
            match sync_once(&dir, client).await {
                Ok(0) => {}
                Ok(n) => tracing::info!("federate: applied {n} new entries from {url}"),
                Err(e) => tracing::warn!("federate: sync from {url} skipped: {e}"),
            }
        }
    }
}

/// Bind and serve until the process ends.
pub async fn serve(addr: std::net::SocketAddr, dir: SharedDir) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("necropolis listening on {addr}");
    axum::serve(listener, router(dir)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use revenant_net::identity::Identity;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn shared() -> SharedDir {
        // Router tests exercise the catalog/ledger paths; open publishing here
        // and cover the account gate separately in publish_requires_account.
        let mut d = Directory::in_memory();
        d.set_require_account(false);
        Arc::new(Mutex::new(d))
    }

    #[tokio::test]
    async fn publish_rejects_tampered_artifact() {
        let k = Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
        let mut a = Artifact::create(&k, ArtifactKind::Skill, "t", "d", b"x", None, 1);
        a.title = "tampered".into();
        let resp = router(shared())
            .oneshot(
                Request::post("/artifacts")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&a).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn publish_is_ledgered_and_derives_catalog() {
        let dir = shared();
        let k = Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
        let a = Artifact::create(&k, ArtifactKind::Skill, "weather-arb", "d", b"payload", None, 1);

        let r = router(dir.clone())
            .oneshot(
                Request::post("/artifacts")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&a).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);

        // The ledger recorded it and the chain verifies.
        assert_eq!(dir.lock().unwrap().ledger.verify_chain().unwrap(), 1);
        // Catalog + reputation were derived from the entry.
        assert_eq!(dir.lock().unwrap().artifacts.len(), 1);
        assert_eq!(dir.lock().unwrap().peers[&k.id()].reputation.published, 1);
    }

    #[tokio::test]
    async fn publish_requires_a_verified_human_account() {
        // Gate ON (the default). Unbound author → 403; after signup→verify→bind → OK.
        let dir = Arc::new(Mutex::new(Directory::in_memory())); // require_account = true
        let k = Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
        let a = Artifact::create(&k, ArtifactKind::Skill, "gated", "d", b"x", None, 1);
        let body = serde_json::to_vec(&a).unwrap();
        let post = || {
            router(dir.clone()).oneshot(
                Request::post("/artifacts")
                    .header("content-type", "application/json")
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
        };
        assert_eq!(post().await.unwrap().status(), StatusCode::FORBIDDEN);

        // Register → verify → bind the author, then publish succeeds.
        let reg = { dir.lock().unwrap().accounts.register("h@x.com").unwrap() };
        dir.lock().unwrap().accounts.verify(&reg.verify_token).unwrap();
        let sig = k.sign_hex(reg.account_key.as_bytes());
        dir.lock().unwrap().accounts.bind(&reg.account_key, &k.id(), &sig).unwrap();
        assert_eq!(post().await.unwrap().status(), StatusCode::OK);
    }

    #[test]
    fn catalog_survives_restart_via_replay() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("n.db").to_string_lossy().to_string();
        let k = Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
        let a = Artifact::create(&k, ArtifactKind::Plugin, "tool", "d", b"wasm", None, 7);
        {
            let d = Directory::open(&p).unwrap();
            let body = serde_json::to_string(&a).unwrap();
            let e = d.ledger.append("artifact", &body, 7).unwrap();
            // (In the server this happens inside publish; here we drive the ledger
            // directly to prove replay rebuilds state on a fresh open.)
            let _ = e;
        }
        // Reopen: the catalog is reconstructed purely from the ledger.
        let d2 = Directory::open(&p).unwrap();
        assert_eq!(d2.artifacts.len(), 1);
        assert!(d2.artifacts.contains_key(&a.id));
        assert_eq!(d2.peers[&k.id()].reputation.published, 1);
    }

    // --- votes, handles, reputation -------------------------------------
    // (uses the `post_json` helper defined later in this module)

    #[tokio::test]
    async fn votes_tally_per_voter_with_retract() {
        let dir = shared();
        let a = Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
        let b = Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
        let t = "scroll-xyz";
        // a upvotes then flips to downvote (latest wins); b upvotes.
        for v in [Vote::create(&a, t, 1, 1), Vote::create(&a, t, -1, 2), Vote::create(&b, t, 1, 1)] {
            assert_eq!(post_json(&dir, "/votes", serde_json::to_vec(&v).unwrap()).await, StatusCode::OK);
        }
        assert_eq!(dir.lock().unwrap().vote_tally(t), Tally { up: 1, down: 1, score: 0 });
    }

    #[tokio::test]
    async fn handle_first_claim_wins_case_insensitive() {
        let dir = shared();
        let a = Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
        let b = Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
        let h1 = Handle::create(&a, "Gravecaller Mordecai", 1);
        assert_eq!(post_json(&dir, "/handles", serde_json::to_vec(&h1).unwrap()).await, StatusCode::OK);
        // b tries the same name in different case/spacing → conflict.
        let h2 = Handle::create(&b, "gravecaller   mordecai", 2);
        assert_eq!(
            post_json(&dir, "/handles", serde_json::to_vec(&h2).unwrap()).await,
            StatusCode::CONFLICT
        );
        // a resolves to the claimed name; b falls back to a deterministic lore-name.
        assert_eq!(dir.lock().unwrap().name_for(&a.id()), ("Gravecaller Mordecai".into(), true));
        assert!(!dir.lock().unwrap().name_for(&b.id()).1);
    }

    #[test]
    fn reputation_credits_distinct_reproductions() {
        let mut d = Directory::in_memory();
        d.set_require_account(false);
        let author = Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
        let art = seed(&mut d, &author, ArtifactKind::Skill, "molt", 1000);
        for _ in 0..3 {
            let p = Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
            let att = Attestation::create(&p, &art.id, true, "ok", 1000);
            let e = d.ledger.append("reproduction", &serde_json::to_string(&att).unwrap(), 1000).unwrap();
            d.apply(&e);
        }
        // 3 distinct accounts × weight 3.0, no decay at age 0 → 9.0.
        let scores = d.reputation_by_pubkey(1000);
        assert!((scores[&author.id()] - 9.0).abs() < 1e-6, "got {:?}", scores.get(&author.id()));
    }

    #[test]
    fn reputation_collapses_two_agents_of_one_account() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("n.db").to_string_lossy().to_string();
        let mut d = Directory::open(&p).unwrap();
        d.set_require_account(false);
        let author = Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
        let art = seed(&mut d, &author, ArtifactKind::Skill, "molt", 1000);
        // One human, two agent keys, both reproduce the same molt.
        let reg = d.accounts.register("ring@x.com").unwrap();
        d.accounts.verify(&reg.verify_token).unwrap();
        for _ in 0..2 {
            let g = Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
            let sig = g.sign_hex(reg.account_key.as_bytes());
            d.accounts.bind(&reg.account_key, &g.id(), &sig).unwrap();
            let att = Attestation::create(&g, &art.id, true, "ok", 1000);
            let e = d.ledger.append("reproduction", &serde_json::to_string(&att).unwrap(), 1000).unwrap();
            d.apply(&e);
        }
        // Both keys collapse to one account: the second vouch is diminished to
        // half — 3.0 × (1 + 0.5) = 4.5, NOT 6.0. Sybil resistance in the score.
        let scores = d.reputation_by_pubkey(1000);
        assert!((scores[&author.id()] - 4.5).abs() < 1e-6, "got {:?}", scores.get(&author.id()));
    }

    // --- pub/sub events + thread convergence ----------------------------

    fn seed_scroll(d: &mut Directory, k: &Identity, body: &str, sigils: Vec<String>, tome: Option<String>, ts: i64) -> Scroll {
        let s = Scroll::create(k, body, vec![], sigils, tome, ts);
        let e = d.ledger.append("scroll", &serde_json::to_string(&s).unwrap(), ts).unwrap();
        d.apply(&e);
        s
    }
    fn seed_reply(d: &mut Directory, k: &Identity, parent: &str, body: &str, ts: i64) {
        let r = Reply::create(k, parent.to_string(), body.to_string(), ts);
        let e = d.ledger.append("reply", &serde_json::to_string(&r).unwrap(), ts).unwrap();
        d.apply(&e);
    }

    #[test]
    fn thread_energy_settles_after_bounded_replies() {
        let mut d = Directory::in_memory();
        let k = Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
        let s = seed_scroll(&mut d, &k, "claim", vec![], None, 1);
        assert!(!d.thread_settled(&s.id)); // 0 replies
        for i in 0..3 {
            seed_reply(&mut d, &k, &s.id, &format!("r{i}"), 10 + i);
        }
        assert!(!d.thread_settled(&s.id)); // 3 replies: 0.6^3 = 0.216 > 0.05
        for i in 3..6 {
            seed_reply(&mut d, &k, &s.id, &format!("r{i}"), 10 + i);
        }
        assert!(d.thread_settled(&s.id)); // 6 replies: 0.6^6 ≈ 0.047 < 0.05 → settled
    }

    #[test]
    fn events_suppress_settled_thread_replies() {
        let mut d = Directory::in_memory();
        let k = Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
        let s = seed_scroll(&mut d, &k, "claim", vec![], None, 1);
        for i in 0..6 {
            seed_reply(&mut d, &k, &s.id, &format!("r{i}"), 10 + i);
        }
        // A fresh subscriber to this (now settled) thread gets the scroll event
        // but NONE of the reply pushes — Brake A. Replies remain on pull.
        let q = EventQuery { thread: Some(s.id.clone()), ..Default::default() };
        let evs = d.events_since(0, &q);
        let kinds: Vec<String> =
            evs.iter().map(|(_, v)| v["kind"].as_str().unwrap().to_string()).collect();
        assert!(kinds.iter().any(|k| k == "scroll"));
        assert!(!kinds.iter().any(|k| k == "reply"), "settled thread must not push replies: {kinds:?}");
    }

    #[test]
    fn events_facet_filter_matches_only_the_sigil() {
        let mut d = Directory::in_memory();
        let k = Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
        let s1 = seed_scroll(&mut d, &k, "perf win", vec!["latency".into()], Some("performance".into()), 1);
        let _s2 = seed_scroll(&mut d, &k, "safety win", vec!["safety".into()], Some("skills".into()), 2);
        let q = EventQuery { sigil: Some("latency".into()), ..Default::default() };
        let evs = d.events_since(0, &q);
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].1["id"], serde_json::json!(s1.id));
    }

    #[tokio::test]
    async fn profile_heartbeat_lands_and_lists() {
        let dir = shared();
        let k = Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
        let specs = revenant_net::profile::MachineSpecs {
            os: "macos".into(),
            arch: "aarch64".into(),
            cpus: 12,
            ram_mb: 65536,
            gpu: Some("M3 Max".into()),
        };
        let p = AgentProfile::create(&k, "Wraith", specs, vec!["coder".into()], 100);
        assert_eq!(post_json(&dir, "/profile", serde_json::to_vec(&p).unwrap()).await, StatusCode::OK);
        // Derived index holds the latest heartbeat with its specs.
        {
            let d = dir.lock().unwrap();
            let stored = &d.profiles[&k.id()];
            assert_eq!(stored.specs.cpus, 12);
            assert_eq!(stored.capabilities, vec!["coder".to_string()]);
        }
        // The public roster endpoint serves.
        let resp = router(dir.clone())
            .oneshot(Request::get("/agents").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn magic_link_login_gates_my_agents() {
        let dir = Arc::new(Mutex::new(Directory::in_memory())); // require_account = true
        let k = Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
        // register → verify → bind an agent.
        {
            let d = dir.lock().unwrap();
            let reg = d.accounts.register("h@x.com").unwrap();
            d.accounts.verify(&reg.verify_token).unwrap();
            let sig = k.sign_hex(reg.account_key.as_bytes());
            d.accounts.bind(&reg.account_key, &k.id(), &sig).unwrap();
        }
        // Magic-link: request a login token, redeem it for a session.
        let ltok = dir.lock().unwrap().accounts.request_login("h@x.com").unwrap().expect("token");
        let session = dir.lock().unwrap().accounts.redeem_login(&ltok).unwrap().expect("session");
        // One-time: redeeming the same login token again fails.
        assert!(dir.lock().unwrap().accounts.redeem_login(&ltok).unwrap().is_none());
        // The session resolves to the account, whose agent is our bound key.
        let id = dir.lock().unwrap().accounts.account_for_session(&session).unwrap();
        assert_eq!(dir.lock().unwrap().accounts.agents_for_id(id), vec![k.id()]);
        // Unknown email → no token, no leak.
        assert!(dir.lock().unwrap().accounts.request_login("nobody@x.com").unwrap().is_none());

        // /account/agents: bearer → 200; missing/bad → 401.
        let with = router(dir.clone())
            .oneshot(
                Request::get("/account/agents")
                    .header("authorization", format!("Bearer {session}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(with.status(), StatusCode::OK);
        let without = router(dir.clone())
            .oneshot(Request::get("/account/agents").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(without.status(), StatusCode::UNAUTHORIZED);
        let bad = router(dir.clone())
            .oneshot(
                Request::get("/account/agents")
                    .header("authorization", "Bearer nope")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad.status(), StatusCode::UNAUTHORIZED);
    }

    // --- federation: replica sync (apply_remote) ------------------------

    /// Publish an artifact into a directory the way the server does — append to
    /// the ledger and fold it into the derived indices — returning it.
    fn seed(dir: &mut Directory, k: &Identity, kind: ArtifactKind, title: &str, ts: i64) -> Artifact {
        let a = Artifact::create(k, kind, title, "d", title.as_bytes(), None, ts);
        let e = dir.ledger.append("artifact", &serde_json::to_string(&a).unwrap(), ts).unwrap();
        dir.apply(&e);
        a
    }

    #[test]
    fn federation_replicates_the_whole_catalog() {
        let k = Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
        let mut origin = Directory::in_memory();
        let a1 = seed(&mut origin, &k, ArtifactKind::Skill, "weather-arb", 1);
        let a2 = seed(&mut origin, &k, ArtifactKind::Plugin, "port-scan", 2);

        let mut replica = Directory::in_memory();
        let applied = replica.apply_remote(&origin.ledger.since(0).unwrap()).unwrap();

        assert_eq!(applied, 2);
        assert_eq!(replica.artifacts.len(), 2);
        assert!(replica.artifacts.contains_key(&a1.id));
        assert!(replica.artifacts.contains_key(&a2.id));
        // Reputation was re-derived on the replica, not trusted from the wire.
        assert_eq!(replica.peers[&k.id()].reputation.published, 2);
        // And the replica's own chain audit passes, head-for-head with origin.
        assert_eq!(replica.ledger.verify_chain().unwrap(), 2);
        assert_eq!(replica.ledger.head_hash().unwrap(), origin.ledger.head_hash().unwrap());
    }

    #[test]
    fn federation_is_idempotent_and_incremental() {
        let k = Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
        let mut origin = Directory::in_memory();
        seed(&mut origin, &k, ArtifactKind::Skill, "one", 1);

        let mut replica = Directory::in_memory();
        assert_eq!(replica.apply_remote(&origin.ledger.since(0).unwrap()).unwrap(), 1);

        // Re-syncing from the replica's head pulls nothing and applies nothing.
        let since = replica.head_seq().unwrap();
        assert_eq!(replica.apply_remote(&origin.ledger.since(since).unwrap()).unwrap(), 0);

        // Origin advances; an incremental sync applies only the new entry.
        seed(&mut origin, &k, ArtifactKind::Signal, "two", 2);
        let since = replica.head_seq().unwrap();
        assert_eq!(replica.apply_remote(&origin.ledger.since(since).unwrap()).unwrap(), 1);
        assert_eq!(replica.artifacts.len(), 2);
    }

    #[test]
    fn federation_rejects_a_forked_stream() {
        let k = Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
        // Replica already has its own history.
        let mut replica = Directory::in_memory();
        seed(&mut replica, &k, ArtifactKind::Skill, "local", 1);

        // A peer whose chain forked from genesis — its entries don't chain onto
        // the replica's head. The whole batch must be refused, nothing written.
        let mut fork = Directory::in_memory();
        seed(&mut fork, &k, ArtifactKind::Skill, "theirs", 9);

        let before = replica.artifacts.len();
        let err = replica.apply_remote(&fork.ledger.since(0).unwrap()).unwrap_err();
        assert!(err.to_string().contains("does not chain"), "got: {err}");
        assert_eq!(replica.artifacts.len(), before, "a rejected sync must not mutate state");
    }

    #[test]
    fn federation_rejects_a_tampered_body_atomically() {
        let k = Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
        let mut origin = Directory::in_memory();
        seed(&mut origin, &k, ArtifactKind::Skill, "good", 1);
        seed(&mut origin, &k, ArtifactKind::Skill, "also-good", 2);

        let mut entries = origin.ledger.since(0).unwrap();
        // Corrupt the second entry's payload without fixing its hash.
        entries[1].body = r#"{"id":"evil"}"#.into();

        let mut replica = Directory::in_memory();
        assert!(replica.apply_remote(&entries).is_err());
        // Pre-validation means the *first*, valid entry was not applied either.
        assert_eq!(replica.artifacts.len(), 0, "a tampered batch is rejected whole");
        assert_eq!(replica.ledger.head_seq().unwrap(), 0);
    }

    #[tokio::test]
    async fn federation_end_to_end_over_http() {
        // A real origin server on an ephemeral port.
        let origin = shared();
        let k = Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
        let a = Artifact::create(&k, ArtifactKind::Skill, "e2e", "d", b"payload", None, 1);
        {
            let mut d = origin.lock().unwrap();
            let e = d.ledger.append("artifact", &serde_json::to_string(&a).unwrap(), 1).unwrap();
            d.apply(&e);
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router(origin)).await.unwrap();
        });

        // A fresh replica pulls the origin's head + entries over HTTP and folds
        // them in, re-verifying every hash on its own box.
        let client = revenant_net::NecropolisClient::new(format!("http://{addr}"));
        let head = client.ledger_head().await.unwrap();
        assert_eq!(head.seq, 1);

        let mut replica = Directory::in_memory();
        let incoming = client.ledger_since(replica.head_seq().unwrap()).await.unwrap();
        let applied = replica.apply_remote(&incoming).unwrap();

        assert_eq!(applied, 1);
        assert!(replica.artifacts.contains_key(&a.id));
        assert_eq!(replica.ledger.head_hash().unwrap(), head.hash);
    }

    #[tokio::test]
    async fn sync_once_federates_a_shared_directory() {
        let origin = shared();
        let k = Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
        let a = Artifact::create(&k, ArtifactKind::Signal, "provider-throttling", "d", b"body", None, 1);
        {
            let mut d = origin.lock().unwrap();
            let e = d.ledger.append("artifact", &serde_json::to_string(&a).unwrap(), 1).unwrap();
            d.apply(&e);
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router(origin)).await.unwrap() });

        let replica = shared();
        let client = revenant_net::NecropolisClient::new(format!("http://{addr}"));
        // First pass mirrors the one entry; second pass is a clean no-op.
        assert_eq!(sync_once(&replica, &client).await.unwrap(), 1);
        assert_eq!(sync_once(&replica, &client).await.unwrap(), 0);
        assert!(replica.lock().unwrap().artifacts.contains_key(&a.id));
    }

    // --- reproductions + Vault posts ------------------------------------

    async fn post_json(dir: &SharedDir, path: &str, body: Vec<u8>) -> StatusCode {
        router(dir.clone())
            .oneshot(
                Request::post(path)
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn reproduction_is_verified_ledgered_and_served() {
        let dir = shared();
        let author = Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
        let peer = Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
        let art = Artifact::create(&author, ArtifactKind::Improvement, "molt", "d", b"diff", None, 1);
        assert_eq!(post_json(&dir, "/artifacts", serde_json::to_vec(&art).unwrap()).await, StatusCode::OK);

        let att = Attestation::create(&peer, &art.id, true, "12/12 pass", 2);
        assert_eq!(post_json(&dir, "/reproductions", serde_json::to_vec(&att).unwrap()).await, StatusCode::OK);

        // Served back for that artifact, and the author got adoption credit.
        // (Single lock scope — holding the guard while re-locking would deadlock.)
        let d = dir.lock().unwrap();
        assert_eq!(d.reproductions[&art.id].len(), 1);
        assert_eq!(d.peers[&author.id()].reputation.adopted, 1);
    }

    #[tokio::test]
    async fn reproduction_rejects_tampered_signature() {
        let dir = shared();
        let peer = Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
        let mut att = Attestation::create(&peer, "molt", true, "ok", 1);
        att.reproduced = false; // flip after signing
        assert_eq!(
            post_json(&dir, "/reproductions", serde_json::to_vec(&att).unwrap()).await,
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn scroll_is_verified_ledgered_and_fed() {
        let dir = shared();
        let author = Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
        let s = Scroll::create(&author, "laid down a 12% latency molt", vec!["molt-abc".into()], vec!["latency".into()], Some("performance".into()), 5);
        assert_eq!(post_json(&dir, "/scrolls", serde_json::to_vec(&s).unwrap()).await, StatusCode::OK);

        // Feed serves it; filter by the referenced artifact matches.
        let r = router(dir.clone())
            .oneshot(Request::get("/scrolls?ref=molt-abc").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(dir.lock().unwrap().scrolls.len(), 1);
    }

    #[tokio::test]
    async fn scroll_rejects_tampered_body() {
        let dir = shared();
        let author = Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
        let mut s = Scroll::create(&author, "hello", vec![], vec![], None, 1);
        s.body = "tampered".into();
        assert_eq!(
            post_json(&dir, "/scrolls", serde_json::to_vec(&s).unwrap()).await,
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn reply_is_verified_ledgered_and_threaded() {
        let dir = shared();
        let author = Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
        let s = Scroll::create(&author, "landed a molt", vec![], vec![], None, 1);
        assert_eq!(post_json(&dir, "/scrolls", serde_json::to_vec(&s).unwrap()).await, StatusCode::OK);

        let peer = Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
        let r = Reply::create(&peer, &s.id, "reproduced it too — solid win", 2);
        let path = format!("/scrolls/{}/replies", s.id);
        assert_eq!(post_json(&dir, &path, serde_json::to_vec(&r).unwrap()).await, StatusCode::OK);
        assert_eq!(dir.lock().unwrap().replies[&s.id].len(), 1);
    }

    #[tokio::test]
    async fn reply_rejects_parent_mismatch() {
        let dir = shared();
        let peer = Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
        let r = Reply::create(&peer, "scrollA", "hi", 1); // signed for scrollA…
        // …but posted under scrollB in the path → rejected.
        assert_eq!(
            post_json(&dir, "/scrolls/scrollB/replies", serde_json::to_vec(&r).unwrap()).await,
            StatusCode::BAD_REQUEST
        );
    }

    // The multi-agent payoff, proven at the consensus layer: three DISTINCT
    // signed identities each reproduce a molt and post over real HTTP; the
    // quorum accrues to the bar and holds. No LLM — just the crypto + ledger +
    // quorum machinery the horde actually runs.
    #[tokio::test]
    async fn quorum_reached_by_distinct_peers_over_http() {
        let dir = shared(); // open publish
        let author = Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
        let art = Artifact::create(&author, ArtifactKind::Improvement, "molt", "d", b"diff", None, 1);
        {
            let mut d = dir.lock().unwrap();
            let e = d.ledger.append("artifact", &serde_json::to_string(&art).unwrap(), 1).unwrap();
            d.apply(&e);
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router(dir)).await.unwrap() });

        let client = revenant_net::NecropolisClient::new(format!("http://{addr}"));
        // Three independent revenants each vouch for the molt.
        for _ in 0..3 {
            let peer = Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
            let att = revenant_net::attest::Attestation::create(&peer, &art.id, true, "3/3 pass", 2);
            client.publish_reproduction(&att).await.unwrap();
        }

        let reps = client.reproductions(&art.id).await.unwrap();
        assert_eq!(reps.len(), 3, "three distinct reproductions on record");
        assert!(reps.iter().all(|a| a.verify()), "every attestation verifies");
        assert!(
            revenant_net::attest::quorum_met(&reps, &art.id, &[], 3),
            "quorum of 3 distinct peers is met"
        );
        assert!(!revenant_net::attest::quorum_met(&reps, &art.id, &[], 4), "but not 4");
    }

    #[test]
    fn reproductions_and_scrolls_survive_restart_via_replay() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("n.db").to_string_lossy().to_string();
        let author = Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
        let peer = Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
        let art = Artifact::create(&author, ArtifactKind::Improvement, "m", "d", b"x", None, 1);
        let att = Attestation::create(&peer, &art.id, true, "", 2);
        let scroll = Scroll::create(&author, "shipped", vec![art.id.clone()], vec![], None, 3);
        {
            let d = Directory::open(&path).unwrap();
            d.ledger.append("artifact", &serde_json::to_string(&art).unwrap(), 1).unwrap();
            d.ledger.append("reproduction", &serde_json::to_string(&att).unwrap(), 2).unwrap();
            d.ledger.append("scroll", &serde_json::to_string(&scroll).unwrap(), 3).unwrap();
        }
        // Reopen: both derived indices rebuild purely from the ledger.
        let d2 = Directory::open(&path).unwrap();
        assert_eq!(d2.reproductions[&art.id].len(), 1);
        assert_eq!(d2.scrolls.len(), 1);
        assert_eq!(d2.scrolls[0].id, scroll.id);
    }
}
