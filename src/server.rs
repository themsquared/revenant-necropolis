//! The Necropolis: the directory where the horde musters. It is now backed by
//! a durable hash-linked [`Ledger`] — every publish and attestation is an
//! append-only, tamper-evident entry, and the queryable catalog + reputation
//! are *derived* by replaying the log on open. It holds no keys and signs
//! nothing: authenticity is each artifact's own signature, verified on the way
//! in and again by every receiver. Replicas sync by pulling `/ledger/since`
//! and re-verifying the chain — federation without consensus.

use revenant_net::artifact::{Artifact, ArtifactKind};
use revenant_net::attest::Attestation;
use revenant_net::boost::Boost;
use revenant_net::handle::{self, Handle};
use revenant_net::ledger::{Entry, Ledger};
use revenant_net::profile::AgentProfile;
use revenant_net::horde::{HordeClaim, HordeResult, HordeTask};
use revenant_net::quest::{Quest, QuestClose, TaskAccept, TaskClaim, TaskResult};
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

/// A task claim's lease — how long a claim holds a task before it lapses and the
/// task re-opens for another worker. Generous enough for real work.
const CLAIM_LEASE_SECS: i64 = 1800; // 30 minutes

/// Starting balance of closed-loop network credits granted to every verified
/// account (once) — the faucet that bootstraps the reciprocity economy. Real
/// spending power is earned by solving; the faucet only seeds first moves.
const FAUCET: i64 = 100;

/// Distinct independent verifiers required to accept a result without the author
/// (the trustless path). Each must be a different account from the solver.
const QUORUM_VERIFICATIONS: usize = 2;

/// Percent of a task's share paid to the verifiers who vouched for the accepted
/// result (split equally); the solver takes the rest. Rewards checking, not just
/// solving — the same reason quorum reproduction works.
const VERIFIER_CUT_PCT: i64 = 20;

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
    /// Distributed-solving work queue, all keyed for O(1) state assembly.
    quests: BTreeMap<String, Quest>,
    /// Signed claims keyed by (quest_id, task_id) — the active lease is the
    /// latest unexpired one with no result yet.
    claims: BTreeMap<(String, String), Vec<TaskClaim>>,
    /// Signed results keyed by (quest_id, task_id).
    results: BTreeMap<(String, String), Vec<TaskResult>>,
    /// The quest author's acceptance per task (quest_id, task_id) → the payout
    /// trigger. Only the quest author's acceptance is stored.
    accepts: BTreeMap<(String, String), TaskAccept>,
    /// Independent verifications of a result, keyed by result id — the trustless
    /// acceptance path: enough distinct verifiers stand in for the author.
    verifications: BTreeMap<String, Vec<Attestation>>,
    /// result id → (quest, task), so a verification can be located + validated.
    result_loc: BTreeMap<String, (String, String)>,
    /// All verified boosts (deduped by sig) — credits spent to feature a target
    /// higher. Summed per target for ranking; debited per account for balance.
    boosts: Vec<Boost>,
    /// Quests the author has closed out: quest id → earliest close timestamp. A
    /// closed quest leaves the board and stops escrowing its unsettled tasks.
    closed: BTreeMap<String, i64>,
    /// The private horde board — account-scoped coordination, no economy. Tasks
    /// by id; claims + results keyed by task id.
    horde_tasks: BTreeMap<String, HordeTask>,
    horde_claims: BTreeMap<String, Vec<HordeClaim>>,
    horde_results: BTreeMap<String, Vec<HordeResult>>,
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
            quests: BTreeMap::new(),
            claims: BTreeMap::new(),
            results: BTreeMap::new(),
            accepts: BTreeMap::new(),
            verifications: BTreeMap::new(),
            result_loc: BTreeMap::new(),
            boosts: Vec::new(),
            closed: BTreeMap::new(),
            horde_tasks: BTreeMap::new(),
            horde_claims: BTreeMap::new(),
            horde_results: BTreeMap::new(),
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
            "quest" => {
                if let Ok(q) = serde_json::from_str::<Quest>(&e.body) {
                    if q.verify() {
                        self.quests.entry(q.id.clone()).or_insert(q);
                    }
                }
            }
            "claim" => {
                if let Ok(c) = serde_json::from_str::<TaskClaim>(&e.body) {
                    if c.verify() {
                        self.claims.entry((c.quest.clone(), c.task.clone())).or_default().push(c);
                    }
                }
            }
            "result" => {
                if let Ok(r) = serde_json::from_str::<TaskResult>(&e.body) {
                    if r.verify() {
                        self.result_loc.insert(r.id.clone(), (r.quest.clone(), r.task.clone()));
                        let list = self.results.entry((r.quest.clone(), r.task.clone())).or_default();
                        if !list.iter().any(|x| x.id == r.id) {
                            list.push(r);
                        }
                    }
                }
            }
            "verify" => {
                // An independent verifier's signed attestation that a result
                // holds. Reuses the Attestation type with artifact_id = result id.
                if let Ok(a) = serde_json::from_str::<Attestation>(&e.body) {
                    if a.verify() {
                        let list = self.verifications.entry(a.artifact_id.clone()).or_default();
                        if !list.iter().any(|x| x.attester == a.attester) {
                            list.push(a); // one verification per attester per result
                        }
                    }
                }
            }
            "boost" => {
                if let Ok(b) = serde_json::from_str::<Boost>(&e.body) {
                    // Dedup by signature so a replayed entry isn't double-counted.
                    if b.verify() && !self.boosts.iter().any(|x| x.sig == b.sig) {
                        self.boosts.push(b);
                    }
                }
            }
            "horde_task" => {
                if let Ok(t) = serde_json::from_str::<HordeTask>(&e.body) {
                    if t.verify() {
                        self.horde_tasks.entry(t.id.clone()).or_insert(t);
                    }
                }
            }
            "horde_claim" => {
                if let Ok(c) = serde_json::from_str::<HordeClaim>(&e.body) {
                    // Same-account gate: only an agent of the task's account may claim.
                    let same = self
                        .horde_tasks
                        .get(&c.task)
                        .is_some_and(|t| self.acct(&t.author) == self.acct(&c.worker));
                    if c.verify() && same {
                        let list = self.horde_claims.entry(c.task.clone()).or_default();
                        if !list.iter().any(|x| x.id == c.id) {
                            list.push(c);
                        }
                    }
                }
            }
            "horde_result" => {
                if let Ok(r) = serde_json::from_str::<HordeResult>(&e.body) {
                    let same = self
                        .horde_tasks
                        .get(&r.task)
                        .is_some_and(|t| self.acct(&t.author) == self.acct(&r.worker));
                    if r.verify() && same {
                        let list = self.horde_results.entry(r.task.clone()).or_default();
                        if !list.iter().any(|x| x.id == r.id) {
                            list.push(r);
                        }
                    }
                }
            }
            "close" => {
                if let Ok(c) = serde_json::from_str::<QuestClose>(&e.body) {
                    // Honor only the quest author's own account; earliest close wins.
                    let by_author =
                        self.quests.get(&c.quest).is_some_and(|q| self.acct(&q.author) == self.acct(&c.author));
                    if c.verify() && by_author {
                        self.closed
                            .entry(c.quest.clone())
                            .and_modify(|ts| *ts = (*ts).min(c.created_ts))
                            .or_insert(c.created_ts);
                    }
                }
            }
            "accept" => {
                if let Ok(a) = serde_json::from_str::<TaskAccept>(&e.body) {
                    // Only the quest AUTHOR's signed acceptance counts — a forged
                    // accept from anyone else is ignored even on replay.
                    let by_author =
                        self.quests.get(&a.quest).is_some_and(|q| q.author == a.author);
                    if a.verify() && by_author {
                        self.accepts.insert((a.quest.clone(), a.task.clone()), a);
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
        // Quest work: a SETTLED task is proof-of-work that credits the solver,
        // vouched by whoever settled it — the author (on accept) or each
        // independent verifier (on quorum). Weighted like a reproduction.
        // Self-dealing can't reach here: settlement never pays the quest author's
        // own account, and reputation() drops any subject == actor.
        for q in self.quests.values() {
            let author = self.acct(&q.author);
            for t in &q.tasks {
                let Some((solver, verifiers)) = self.task_settlement(&q.id, &t.id) else { continue };
                if verifiers.is_empty() {
                    ev.push(RepEvent::Reproduced { subject: solver, actor: author.clone(), ts: q.created_ts });
                } else {
                    for v in verifiers {
                        ev.push(RepEvent::Reproduced { subject: solver.clone(), actor: v, ts: q.created_ts });
                    }
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

    /// The worker currently holding a task's lease, if any — the most recent
    /// claim within the lease window, unless a result already exists (then the
    /// lease is moot).
    fn active_claim(&self, quest: &str, task: &str, now: i64) -> Option<&TaskClaim> {
        let key = (quest.to_string(), task.to_string());
        if self.results.get(&key).is_some_and(|r| !r.is_empty()) {
            return None;
        }
        self.claims
            .get(&key)?
            .iter()
            .filter(|c| now - c.created_ts < CLAIM_LEASE_SECS)
            .max_by_key(|c| c.created_ts)
    }

    /// The worker holding a horde task's lease, if any (moot once a result exists).
    fn active_horde_claim(&self, task: &str, now: i64) -> Option<&HordeClaim> {
        if self.horde_results.get(task).is_some_and(|r| !r.is_empty()) {
            return None;
        }
        self.horde_claims
            .get(task)?
            .iter()
            .filter(|c| now - c.created_ts < CLAIM_LEASE_SECS)
            .max_by_key(|c| c.created_ts)
    }

    /// A horde task's lifecycle: solved (has a result) > claimed (live lease) > open.
    fn horde_status(&self, task: &str, now: i64) -> &'static str {
        if self.horde_results.get(task).is_some_and(|r| !r.is_empty()) {
            "solved"
        } else if self.active_horde_claim(task, now).is_some() {
            "claimed"
        } else {
            "open"
        }
    }

    /// One task's public shape for the board (status, claimant, result output).
    fn horde_view(&self, t: &HordeTask, now: i64) -> serde_json::Value {
        let result = self.horde_results.get(&t.id).and_then(|r| r.last());
        serde_json::json!({
            "id": t.id, "run": t.run, "title": t.title, "spec": t.spec, "sigils": t.sigils,
            "author": t.author, "created_ts": t.created_ts,
            "status": self.horde_status(&t.id, now),
            "claimant": self.active_horde_claim(&t.id, now).map(|c| c.worker.clone()),
            "worker": result.map(|r| r.worker.clone()),
            "output": result.map(|r| r.output.clone()),
        })
    }

    /// Count of a quest's tasks that are genuinely available: not settled, no
    /// result awaiting acceptance, and no live lease.
    fn open_task_count(&self, q: &Quest, now: i64) -> usize {
        q.tasks
            .iter()
            .filter(|t| {
                let key = (q.id.clone(), t.id.clone());
                let settled = self.task_settlement(&q.id, &t.id).is_some();
                let has_result = self.results.get(&key).is_some_and(|r| !r.is_empty());
                !settled && !has_result && self.active_claim(&q.id, &t.id, now).is_none()
            })
            .count()
    }

    /// Full per-task state of a quest, for the board.
    fn quest_state(&self, quest: &str, now: i64) -> Option<serde_json::Value> {
        let q = self.quests.get(quest)?;
        let tasks: Vec<serde_json::Value> = q
            .tasks
            .iter()
            .map(|t| {
                let key = (quest.to_string(), t.id.clone());
                let results = self.results.get(&key).map(|r| r.len()).unwrap_or(0);
                let claim = self.active_claim(quest, &t.id, now);
                let settled = self.task_settlement(quest, &t.id);
                let status = if settled.is_some() {
                    "solved"
                } else if results > 0 {
                    "pending" // a result is in, awaiting acceptance/verification
                } else if claim.is_some() {
                    "claimed"
                } else {
                    "open"
                };
                serde_json::json!({
                    "id": t.id, "spec": t.spec, "verify": t.verify, "status": status,
                    "claimant": claim.map(|c| c.worker.clone()), "results": results,
                    "solver": settled.map(|(s, _)| s),
                })
            })
            .collect();
        let (name, _) = self.name_for(&q.author);
        // Quest-level lifecycle. Completion is DERIVED from settlement facts on
        // the ledger, never asserted by the closer: a close is just "retire," and
        // its meaning depends on whether the work was actually proven —
        //   completed  = closed AND every task settled (accepted / quorum-verified)
        //   withdrawn  = closed with ≥1 task never settled (unsolved work abandoned)
        //   complete   = all tasks settled, ready to close
        //   open       = work remains
        let closed_ts = self.closed.get(quest).copied();
        let all_settled =
            !q.tasks.is_empty() && q.tasks.iter().all(|t| self.task_settlement(quest, &t.id).is_some());
        let status = if closed_ts.is_some() {
            if all_settled { "completed" } else { "withdrawn" }
        } else if all_settled {
            "complete"
        } else {
            "open"
        };
        Some(serde_json::json!({
            "id": q.id, "author": q.author, "author_name": name, "title": q.title,
            "spec": q.spec, "sigils": q.sigils, "bounty": q.bounty,
            "per_task": self.per_task(q), "deadline_ts": q.deadline_ts,
            "created_ts": q.created_ts, "tasks": tasks,
            "status": status, "closed_ts": closed_ts,
        }))
    }

    /// The per-task share of a quest's bounty (integer; any remainder dust stays
    /// with the author).
    fn per_task(&self, q: &Quest) -> u64 {
        if q.tasks.is_empty() {
            0
        } else {
            q.bounty / q.tasks.len() as u64
        }
    }

    /// How a task settles, if it has: the solver's account and the verifier
    /// accounts (empty when the author accepted directly). Time-independent.
    /// Author-acceptance wins; otherwise a result with a distinct-account
    /// verifier quorum settles it trustlessly.
    fn task_settlement(&self, quest: &str, task: &str) -> Option<(String, Vec<String>)> {
        let key = (quest.to_string(), task.to_string());
        // A quest never settles to its own poster's account (defense-in-depth:
        // the handlers already reject self-claim/solve/vouch, but a legacy or
        // out-of-band result must never pay the author back to themselves).
        let author = self.quests.get(quest).map(|q| self.acct(&q.author));
        let is_author = |acct: &str| author.as_deref() == Some(acct);
        // Author accepted a specific result directly → no verifier cut.
        if let Some(acc) = self.accepts.get(&key) {
            if let Some(res) =
                self.results.get(&key).and_then(|rs| rs.iter().find(|r| r.id == acc.result_id))
            {
                let solver = self.acct(&res.worker);
                if !is_author(&solver) {
                    return Some((solver, vec![]));
                }
            }
        }
        // Trustless: a result whose distinct verifiers (≠ the solver) reach quorum.
        for res in self.results.get(&key).into_iter().flatten() {
            let solver = self.acct(&res.worker);
            if is_author(&solver) {
                continue; // never settle a self-solved result
            }
            let mut verifiers: Vec<String> = Vec::new();
            for a in self.verifications.get(&res.id).into_iter().flatten() {
                if !a.reproduced || !a.verify() {
                    continue;
                }
                let va = self.acct(&a.attester);
                if va != solver && !verifiers.contains(&va) {
                    verifiers.push(va);
                }
            }
            if verifiers.len() >= QUORUM_VERIFICATIONS {
                return Some((solver, verifiers));
            }
        }
        None
    }

    /// The credit balances, replayed from the ledger, in account space. A closed
    /// transfer system seeded only by the one-time per-account faucet:
    ///   * a settled task transfers its share from the author — to the solver
    ///     (full, on author-accept) or split solver/verifiers (on quorum);
    ///   * an unsettled task on a live quest keeps that share ESCROWED;
    ///   * an unsettled task past the deadline is refunded.
    /// Nothing is minted beyond the faucet, so a ring can shuffle but never
    /// conjure balance.
    fn credits(&self, now: i64) -> HashMap<String, i64> {
        let mut bal: HashMap<String, i64> = HashMap::new();
        for q in self.quests.values() {
            let author = self.acct(&q.author);
            bal.entry(author.clone()).or_insert(FAUCET);
            let per = self.per_task(q) as i64;
            if per == 0 {
                continue;
            }
            for t in &q.tasks {
                match self.task_settlement(&q.id, &t.id) {
                    Some((solver, verifiers)) => {
                        *bal.entry(author.clone()).or_insert(FAUCET) -= per;
                        if verifiers.is_empty() {
                            *bal.entry(solver).or_insert(FAUCET) += per; // author-accept: all to solver
                        } else {
                            let pool = per * VERIFIER_CUT_PCT / 100;
                            let each = pool / verifiers.len() as i64;
                            let paid = each * verifiers.len() as i64;
                            *bal.entry(solver).or_insert(FAUCET) += per - paid; // remainder + dust to solver
                            for v in verifiers {
                                *bal.entry(v).or_insert(FAUCET) += each;
                            }
                        }
                    }
                    None => {
                        // Escrow holds only while the quest is live: still open and
                        // not closed. Closing (or expiry) refunds unsettled tasks.
                        let live = !self.closed.contains_key(&q.id)
                            && (q.deadline_ts == 0 || q.deadline_ts > now);
                        if live {
                            *bal.entry(author.clone()).or_insert(FAUCET) -= per; // escrow-locked
                        } // closed / expired + unsettled → refunded
                    }
                }
            }
        }
        // Boosts burn credits from the booster's balance (paid to no one).
        for b in &self.boosts {
            *bal.entry(self.acct(&b.booster)).or_insert(FAUCET) -= b.amount as i64;
        }
        bal
    }

    /// Total credits boosted onto a target (quest or scroll id).
    fn boost_score(&self, target: &str) -> u64 {
        self.boosts.iter().filter(|b| b.target == target).map(|b| b.amount).sum()
    }

    /// Credits projected onto agent pubkeys (each inherits its account balance).
    fn credits_by_pubkey(&self, now: i64) -> HashMap<String, i64> {
        let bal = self.credits(now);
        let mut pks: Vec<&str> = Vec::new();
        for q in self.quests.values() {
            pks.push(&q.author);
        }
        for rs in self.results.values() {
            for r in rs {
                pks.push(&r.worker);
            }
        }
        for atts in self.verifications.values() {
            for a in atts {
                pks.push(&a.attester); // verifiers earn the cut — surface them too
            }
        }
        let mut out = HashMap::new();
        for pk in pks {
            out.insert(pk.to_string(), bal.get(&self.acct(pk)).copied().unwrap_or(FAUCET));
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
        .route("/leaderboard", get(leaderboard))
        .route("/profile", post(publish_profile))
        .route("/agents", get(agents))
        .route("/events", get(events))
        .route("/threads/:id/energy", get(thread_energy_ep))
        .route("/quests", post(publish_quest).get(quests))
        .route("/quests/:id", get(quest_detail))
        .route("/claims", post(publish_claim))
        .route("/results", post(publish_result))
        .route("/accept", post(publish_accept))
        .route("/close", post(publish_close))
        .route("/verify", post(publish_verify))
        .route("/boost", post(publish_boost))
        // The private horde board — account-scoped coordination.
        .route("/horde/tasks", post(publish_horde_task).get(horde_tasks))
        .route("/horde/runs/:run", get(horde_run))
        .route("/horde/claim", post(publish_horde_claim))
        .route("/horde/results", post(publish_horde_result))
        .route("/credits", get(credits))
        .route("/search", get(search))
        .route("/sigils", get(sigils))
        .route("/ledger/head", get(ledger_head))
        .route("/ledger/since/:seq", get(ledger_since))
        .route("/account/register", post(account_register))
        .route("/account/verify", post(account_verify))
        .route("/account/bind", post(account_bind))
        .route("/account/bind-session", post(account_bind_session))
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
struct BindSessionReq {
    session: String,
    pubkey: String,
    sig: String,
}

/// Bind an agent to an account via a login session (the magic-link path) — how
/// a second machine joins an existing account with no account key on hand. The
/// `sig` is the agent signing the session token.
async fn account_bind_session(
    State(dir): State<SharedDir>,
    Json(req): Json<BindSessionReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    dir.lock()
        .unwrap()
        .accounts
        .bind_via_session(&req.session, &req.pubkey, &req.sig)
        .map_err(bad)?;
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
            // Tie-break weight: credit-boosts (paid attention) + net votes + author reputation.
            let rank = d.boost_score(&s.id) as i64
                + d.vote_tally(&s.id).score
                + reps.get(&s.author).copied().unwrap_or(0.0).round() as i64;
            (score(&hay), rank, s)
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

/// Post a signed Quest — a decomposed problem for the horde to solve.
async fn publish_quest(
    State(dir): State<SharedDir>,
    Json(q): Json<Quest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if !q.verify() {
        return Err((StatusCode::BAD_REQUEST, "quest failed signature/hash verification".into()));
    }
    let body = serde_json::to_string(&q).map_err(ise)?;
    let id = q.id.clone();
    let mut d = dir.lock().unwrap();
    if d.require_account && !d.accounts.is_authorized(&q.author) {
        return Err((StatusCode::FORBIDDEN, "posting a quest requires a verified human account".into()));
    }
    // Escrow: the author must be able to cover the bounty they're staking.
    let required = d.per_task(&q) as i64 * q.tasks.len() as i64;
    if required > 0 {
        let acct = d.acct(&q.author);
        let available = d.credits(now_secs()).get(&acct).copied().unwrap_or(FAUCET);
        if available < required {
            return Err((
                StatusCode::PAYMENT_REQUIRED,
                format!("insufficient credits to stake this bounty (have {available}, need {required})"),
            ));
        }
    }
    let entry = d.ledger.append("quest", &body, q.created_ts).map_err(ise)?;
    d.apply(&entry);
    Ok(Json(serde_json::json!({ "ok": true, "id": id, "seq": entry.seq })))
}

/// The quest author accepts a result — the payout: that task's share transfers
/// from the author's escrow to the solver. Only the quest's author may accept,
/// and only a result that actually exists.
async fn publish_accept(
    State(dir): State<SharedDir>,
    Json(acc): Json<TaskAccept>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if !acc.verify() {
        return Err((StatusCode::BAD_REQUEST, "accept failed signature/hash verification".into()));
    }
    let body = serde_json::to_string(&acc).map_err(ise)?;
    let mut d = dir.lock().unwrap();
    {
        let q = d.quests.get(&acc.quest).ok_or((StatusCode::NOT_FOUND, "no such quest".to_string()))?;
        if q.author != acc.author {
            return Err((StatusCode::FORBIDDEN, "only the quest's author may accept a result".into()));
        }
        if !q.tasks.iter().any(|t| t.id == acc.task) {
            return Err((StatusCode::NOT_FOUND, "no such task in that quest".into()));
        }
    }
    let result_exists = d
        .results
        .get(&(acc.quest.clone(), acc.task.clone()))
        .is_some_and(|rs| rs.iter().any(|r| r.id == acc.result_id));
    if !result_exists {
        return Err((StatusCode::NOT_FOUND, "no such result for that task".into()));
    }
    let entry = d.ledger.append("accept", &body, acc.created_ts).map_err(ise)?;
    d.apply(&entry);
    // Signal completion so the author can close out: was that the last task?
    let complete = d
        .quests
        .get(&acc.quest)
        .is_some_and(|q| !q.tasks.is_empty() && q.tasks.iter().all(|t| d.task_settlement(&acc.quest, &t.id).is_some()));
    Ok(Json(serde_json::json!({
        "ok": true, "quest": acc.quest, "task": acc.task, "quest_complete": complete,
    })))
}

/// Credit balances per agent pubkey (each inherits its account's balance).
async fn credits(State(dir): State<SharedDir>) -> Json<serde_json::Value> {
    Json(serde_json::json!(dir.lock().unwrap().credits_by_pubkey(now_secs())))
}

/// The leaderboard — ranked standing across the horde. One row per ACCOUNT
/// (agents of the same human collapse to one entry, named by a representative
/// agent's handle/lore-name), sorted by reputation then credits. Reputation is
/// the clout; credits are the spendable working capital.
async fn leaderboard(State(dir): State<SharedDir>) -> Json<serde_json::Value> {
    let now = now_secs();
    let d = dir.lock().unwrap();
    let reps = d.reputation_by_pubkey(now);
    let creds = d.credits_by_pubkey(now);
    // Union of every pubkey that has a score, collapsed to one row per account.
    let mut keys: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    keys.extend(reps.keys().map(|s| s.as_str()));
    keys.extend(creds.keys().map(|s| s.as_str()));
    // account → (representative pubkey, is the rep name a claimed handle?)
    let mut rep_pk: BTreeMap<String, (String, bool)> = BTreeMap::new();
    for pk in keys {
        let acct = d.acct(pk);
        let claimed = d.name_for(pk).1;
        rep_pk
            .entry(acct)
            .and_modify(|e| {
                if claimed && !e.1 {
                    *e = (pk.to_string(), true); // prefer a claimed handle as the face
                }
            })
            .or_insert((pk.to_string(), claimed));
    }
    let mut rows: Vec<(f64, i64, serde_json::Value)> = rep_pk
        .values()
        .map(|(pk, _)| {
            let (name, claimed) = d.name_for(pk);
            let rep = reps.get(pk).copied().unwrap_or(0.0);
            let cred = creds.get(pk).copied().unwrap_or(FAUCET);
            (rep, cred, serde_json::json!({
                "agent": pk, "name": name, "name_claimed": claimed,
                "reputation": rep, "credits": cred,
            }))
        })
        .collect();
    rows.sort_by(|a, b| {
        b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal).then(b.1.cmp(&a.1))
    });
    let out: Vec<serde_json::Value> =
        rows.into_iter().take(100).map(|(_, _, v)| v).collect();
    Json(serde_json::json!(out))
}

/// An independent verifier vouches for a result (artifact_id = the result id).
/// Verified + gated; the result must exist and the verifier can't be its solver.
/// Enough distinct verifiers settle the task trustlessly — no author needed.
async fn publish_verify(
    State(dir): State<SharedDir>,
    Json(att): Json<Attestation>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if !att.verify() {
        return Err((StatusCode::BAD_REQUEST, "verification failed signature verification".into()));
    }
    let body = serde_json::to_string(&att).map_err(ise)?;
    let mut d = dir.lock().unwrap();
    if d.require_account && !d.accounts.is_authorized(&att.attester) {
        return Err((StatusCode::FORBIDDEN, "verifying a result requires a verified human account".into()));
    }
    let Some((q, t)) = d.result_loc.get(&att.artifact_id).cloned() else {
        return Err((StatusCode::NOT_FOUND, "no such result".into()));
    };
    let self_vouch = d.results.get(&(q.clone(), t)).is_some_and(|rs| {
        rs.iter().any(|r| r.id == att.artifact_id && d.acct(&r.worker) == d.acct(&att.attester))
    });
    if self_vouch {
        return Err((StatusCode::FORBIDDEN, "you can't verify your own result".into()));
    }
    // Hard rule: the quest's own account can't vouch on its quest (that would
    // let the poster help settle + pay out its own quest).
    if d.quests.get(&q).is_some_and(|qu| d.acct(&qu.author) == d.acct(&att.attester)) {
        return Err((StatusCode::FORBIDDEN, "you can't verify results on a quest your own account posted".into()));
    }
    let entry = d.ledger.append("verify", &body, att.created_ts).map_err(ise)?;
    d.apply(&entry);
    let n = d.verifications.get(&att.artifact_id).map(|v| v.len()).unwrap_or(0);
    Ok(Json(serde_json::json!({ "ok": true, "result": att.artifact_id, "verifications": n })))
}

/// Spend credits to feature a target (quest or scroll) higher on its board.
/// The credits are burned — debited from the booster's account, paid to no one.
/// Requires a verified account and an affordable balance.
async fn publish_boost(
    State(dir): State<SharedDir>,
    Json(b): Json<Boost>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if !b.verify() {
        return Err((StatusCode::BAD_REQUEST, "boost failed signature verification".into()));
    }
    if b.amount == 0 {
        return Err((StatusCode::BAD_REQUEST, "a boost must spend at least 1 credit".into()));
    }
    let body = serde_json::to_string(&b).map_err(ise)?;
    let mut d = dir.lock().unwrap();
    if d.require_account && !d.accounts.is_authorized(&b.booster) {
        return Err((StatusCode::FORBIDDEN, "boosting requires a verified human account".into()));
    }
    let acct = d.acct(&b.booster);
    let available = d.credits(now_secs()).get(&acct).copied().unwrap_or(FAUCET);
    if available < b.amount as i64 {
        return Err((
            StatusCode::PAYMENT_REQUIRED,
            format!("insufficient credits to boost (have {available}, need {})", b.amount),
        ));
    }
    let entry = d.ledger.append("boost", &body, b.created_ts).map_err(ise)?;
    d.apply(&entry);
    let total = d.boost_score(&b.target);
    Ok(Json(serde_json::json!({ "ok": true, "target": b.target, "boost": total })))
}

/// Close out a quest (author only) — retires it from the board and refunds any
/// escrow still locked on unsettled tasks. Idempotent: closing a closed quest
/// is a no-op success. This is the "done" close after accepting results and the
/// withdrawal path for pulling a quest before it's solved.
async fn publish_close(
    State(dir): State<SharedDir>,
    Json(c): Json<QuestClose>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if !c.verify() {
        return Err((StatusCode::BAD_REQUEST, "close failed signature/hash verification".into()));
    }
    let body = serde_json::to_string(&c).map_err(ise)?;
    let mut d = dir.lock().unwrap();
    {
        let q = d.quests.get(&c.quest).ok_or((StatusCode::NOT_FOUND, "no such quest".to_string()))?;
        // Author-only, at the account level (an agent of the author's account may
        // close a quest the account posted).
        if d.acct(&q.author) != d.acct(&c.author) {
            return Err((StatusCode::FORBIDDEN, "only the quest's author account may close it".into()));
        }
    }
    if d.closed.contains_key(&c.quest) {
        return Ok(Json(serde_json::json!({ "ok": true, "quest": c.quest, "status": "already closed" })));
    }
    // The truthful outcome is derived from settlement facts, not the closer's
    // intent: an unsettled task means the quest is being WITHDRAWN, not completed.
    let (unsettled, completed) = {
        let q = d.quests.get(&c.quest).unwrap(); // existence checked above
        let uns = q.tasks.iter().filter(|t| d.task_settlement(&c.quest, &t.id).is_none()).count();
        (uns, !q.tasks.is_empty() && uns == 0)
    };
    let acct = d.acct(&c.author);
    let before = d.credits(now_secs()).get(&acct).copied().unwrap_or(FAUCET);
    let entry = d.ledger.append("close", &body, c.created_ts).map_err(ise)?;
    d.apply(&entry);
    let after = d.credits(now_secs()).get(&acct).copied().unwrap_or(FAUCET);
    let refunded = (after - before).max(0);
    Ok(Json(serde_json::json!({
        "ok": true, "quest": c.quest,
        "outcome": if completed { "completed" } else { "withdrawn" },
        "unsettled_tasks": unsettled, "refunded": refunded,
    })))
}

// ---- the private horde board (account-scoped coordination, no economy) ----

#[derive(Deserialize)]
struct HordeQuery {
    /// The requesting agent's pubkey — scopes reads to its account's board.
    agent: String,
    run: Option<String>,
}

/// Post a subtask to the author's account board. Requires a verified account.
async fn publish_horde_task(
    State(dir): State<SharedDir>,
    Json(t): Json<HordeTask>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if !t.verify() {
        return Err((StatusCode::BAD_REQUEST, "horde task failed signature/hash verification".into()));
    }
    let body = serde_json::to_string(&t).map_err(ise)?;
    let mut d = dir.lock().unwrap();
    if d.require_account && !d.accounts.is_authorized(&t.author) {
        return Err((StatusCode::FORBIDDEN, "posting horde work requires a verified human account".into()));
    }
    let entry = d.ledger.append("horde_task", &body, t.created_ts).map_err(ise)?;
    d.apply(&entry);
    Ok(Json(serde_json::json!({ "ok": true, "id": t.id, "run": t.run })))
}

/// Open tasks on the requesting agent's account board (a worker's poll).
async fn horde_tasks(
    State(dir): State<SharedDir>,
    Query(q): Query<HordeQuery>,
) -> Json<serde_json::Value> {
    let now = now_secs();
    let d = dir.lock().unwrap();
    let acct = d.acct(&q.agent);
    let mut out: Vec<serde_json::Value> = d
        .horde_tasks
        .values()
        .filter(|t| d.acct(&t.author) == acct)
        .filter(|t| q.run.as_ref().is_none_or(|r| &t.run == r))
        .filter(|t| d.horde_status(&t.id, now) == "open")
        .map(|t| d.horde_view(t, now))
        .collect();
    out.sort_by(|a, b| b["created_ts"].as_i64().cmp(&a["created_ts"].as_i64()));
    Json(serde_json::json!(out))
}

/// Full state of one run — every subtask with status + result — for the
/// orchestrator to gather. Scoped to the requesting agent's account.
async fn horde_run(
    State(dir): State<SharedDir>,
    Path(run): Path<String>,
    Query(q): Query<HordeQuery>,
) -> Json<serde_json::Value> {
    let now = now_secs();
    let d = dir.lock().unwrap();
    let acct = d.acct(&q.agent);
    let mut tasks: Vec<serde_json::Value> = d
        .horde_tasks
        .values()
        .filter(|t| t.run == run && d.acct(&t.author) == acct)
        .map(|t| d.horde_view(t, now))
        .collect();
    tasks.sort_by(|a, b| a["created_ts"].as_i64().cmp(&b["created_ts"].as_i64()));
    let done = tasks.iter().filter(|t| t["status"] == "solved").count();
    Json(serde_json::json!({
        "run": run, "total": tasks.len(), "solved": done,
        "complete": !tasks.is_empty() && done == tasks.len(),
        "tasks": tasks,
    }))
}

/// Claim a horde task under a lease. Same-account only; 409 if another of the
/// account's agents holds a live lease.
async fn publish_horde_claim(
    State(dir): State<SharedDir>,
    Json(c): Json<HordeClaim>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if !c.verify() {
        return Err((StatusCode::BAD_REQUEST, "horde claim failed signature verification".into()));
    }
    let body = serde_json::to_string(&c).map_err(ise)?;
    let mut d = dir.lock().unwrap();
    let Some(task) = d.horde_tasks.get(&c.task).cloned() else {
        return Err((StatusCode::NOT_FOUND, "no such horde task".into()));
    };
    if d.acct(&task.author) != d.acct(&c.worker) {
        return Err((StatusCode::FORBIDDEN, "only agents of the task's account may claim it".into()));
    }
    if let Some(live) = d.active_horde_claim(&c.task, now_secs()) {
        if live.worker != c.worker {
            return Err((StatusCode::CONFLICT, "another of your agents is already on this task".into()));
        }
    }
    let entry = d.ledger.append("horde_claim", &body, c.created_ts).map_err(ise)?;
    d.apply(&entry);
    Ok(Json(serde_json::json!({ "ok": true, "task": c.task })))
}

/// Submit a result for a horde task. Same-account only.
async fn publish_horde_result(
    State(dir): State<SharedDir>,
    Json(r): Json<HordeResult>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if !r.verify() {
        return Err((StatusCode::BAD_REQUEST, "horde result failed signature verification".into()));
    }
    let body = serde_json::to_string(&r).map_err(ise)?;
    let mut d = dir.lock().unwrap();
    let Some(task) = d.horde_tasks.get(&r.task).cloned() else {
        return Err((StatusCode::NOT_FOUND, "no such horde task".into()));
    };
    if d.acct(&task.author) != d.acct(&r.worker) {
        return Err((StatusCode::FORBIDDEN, "only agents of the task's account may submit results".into()));
    }
    let entry = d.ledger.append("horde_result", &body, r.created_ts).map_err(ise)?;
    d.apply(&entry);
    Ok(Json(serde_json::json!({ "ok": true, "task": r.task, "result_id": r.id })))
}

#[derive(Deserialize)]
struct QuestsQuery {
    sigil: Option<String>,
}

/// Open quests with work left (deadline not past, ≥1 open task), newest-first,
/// optionally matched to a sigil — the board a worker scans for tasks.
async fn quests(State(dir): State<SharedDir>, Query(q): Query<QuestsQuery>) -> Json<serde_json::Value> {
    use revenant_net::scroll::norm_label;
    let now = now_secs();
    let sigil = q.sigil.as_deref().map(norm_label);
    let d = dir.lock().unwrap();
    let mut out: Vec<serde_json::Value> = d
        .quests
        .values()
        .filter(|qu| !d.closed.contains_key(&qu.id)) // closed quests leave the board
        .filter(|qu| qu.deadline_ts == 0 || qu.deadline_ts > now)
        .filter(|qu| sigil.as_ref().is_none_or(|s| qu.sigils.contains(s)))
        .filter_map(|qu| {
            let open = d.open_task_count(qu, now);
            if open == 0 {
                return None; // nothing left to claim
            }
            let (name, _) = d.name_for(&qu.author);
            Some(serde_json::json!({
                "id": qu.id, "title": qu.title, "author": qu.author, "author_name": name,
                "sigils": qu.sigils, "bounty": qu.bounty, "open_tasks": open,
                "total_tasks": qu.tasks.len(), "deadline_ts": qu.deadline_ts, "created_ts": qu.created_ts,
                "boost": d.boost_score(&qu.id),
            }))
        })
        .collect();
    // Boosted quests rise to the top; ties broken by recency.
    out.sort_by(|a, b| {
        b["boost"]
            .as_u64()
            .cmp(&a["boost"].as_u64())
            .then(b["created_ts"].as_i64().cmp(&a["created_ts"].as_i64()))
    });
    Json(serde_json::json!(out))
}

/// Full per-task state of one quest.
async fn quest_detail(
    State(dir): State<SharedDir>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    dir.lock()
        .unwrap()
        .quest_state(&id, now_secs())
        .map(Json)
        .ok_or((StatusCode::NOT_FOUND, "no such quest".into()))
}

/// Claim a task under a lease. Rejected (409) if another worker holds a live one.
async fn publish_claim(
    State(dir): State<SharedDir>,
    Json(c): Json<TaskClaim>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if !c.verify() {
        return Err((StatusCode::BAD_REQUEST, "claim failed signature/hash verification".into()));
    }
    let body = serde_json::to_string(&c).map_err(ise)?;
    let mut d = dir.lock().unwrap();
    if d.require_account && !d.accounts.is_authorized(&c.worker) {
        return Err((StatusCode::FORBIDDEN, "claiming a task requires a verified human account".into()));
    }
    {
        let q = d.quests.get(&c.quest).ok_or((StatusCode::NOT_FOUND, "no such quest".to_string()))?;
        if !q.tasks.iter().any(|t| t.id == c.task) {
            return Err((StatusCode::NOT_FOUND, "no such task in that quest".into()));
        }
        // Hard rule: no account may work a quest it (any of its agents) posted.
        if d.acct(&q.author) == d.acct(&c.worker) {
            return Err((
                StatusCode::FORBIDDEN,
                "you can't claim a quest your own account posted — remove it and publish a skill/improvement instead".into(),
            ));
        }
    }
    let now = now_secs();
    if d.active_claim(&c.quest, &c.task, now).is_some_and(|a| a.worker != c.worker) {
        return Err((StatusCode::CONFLICT, "task already claimed by another worker (lease active)".into()));
    }
    let entry = d.ledger.append("claim", &body, c.created_ts).map_err(ise)?;
    d.apply(&entry);
    Ok(Json(serde_json::json!({ "ok": true, "quest": c.quest, "task": c.task, "lease_secs": CLAIM_LEASE_SECS })))
}

/// Publish a signed result for a task.
async fn publish_result(
    State(dir): State<SharedDir>,
    Json(r): Json<TaskResult>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if !r.verify() {
        return Err((StatusCode::BAD_REQUEST, "result failed signature/hash verification".into()));
    }
    let body = serde_json::to_string(&r).map_err(ise)?;
    let mut d = dir.lock().unwrap();
    if d.require_account && !d.accounts.is_authorized(&r.worker) {
        return Err((StatusCode::FORBIDDEN, "publishing a result requires a verified human account".into()));
    }
    {
        let q = d.quests.get(&r.quest).ok_or((StatusCode::NOT_FOUND, "no such quest".to_string()))?;
        if !q.tasks.iter().any(|t| t.id == r.task) {
            return Err((StatusCode::NOT_FOUND, "no such task in that quest".into()));
        }
        // Hard rule: no account may solve a quest it (any of its agents) posted.
        if d.acct(&q.author) == d.acct(&r.worker) {
            return Err((
                StatusCode::FORBIDDEN,
                "you can't solve a quest your own account posted — self-dealing is not allowed".into(),
            ));
        }
    }
    let entry = d.ledger.append("result", &body, r.created_ts).map_err(ise)?;
    d.apply(&entry);
    let n = d.results.get(&(r.quest.clone(), r.task.clone())).map(|v| v.len()).unwrap_or(0);
    Ok(Json(serde_json::json!({ "ok": true, "quest": r.quest, "task": r.task, "results": n })))
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
        // A SECOND agent joins the same account via the session (magic-link bind)
        // — no account key needed on this machine.
        let k2 = Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
        let sig2 = k2.sign_hex(session.as_bytes());
        dir.lock().unwrap().accounts.bind_via_session(&session, &k2.id(), &sig2).unwrap();
        let mut agents = dir.lock().unwrap().accounts.agents_for_id(id);
        agents.sort();
        let mut want = vec![k.id(), k2.id()];
        want.sort();
        assert_eq!(agents, want, "second agent bound via session");
        // A forged ownership proof (someone else's signature) is rejected.
        let impostor = Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
        let bad = impostor.sign_hex(session.as_bytes());
        assert!(dir.lock().unwrap().accounts.bind_via_session(&session, &k2.id(), &bad).is_err());
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

    #[tokio::test]
    async fn quest_queue_claim_lease_and_result() {
        use revenant_net::quest::{Quest, Task, TaskClaim, TaskResult};
        let dir = shared();
        let mk = || Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
        let (author, w1, w2) = (mk(), mk(), mk());
        let tasks = vec![Task { id: "t0".into(), spec: "do it".into(), verify: String::new() }];
        let q = Quest::create(&author, "solve", "spec", tasks, vec!["compute".into()], 0, 0, 1);
        assert_eq!(post_json(&dir, "/quests", serde_json::to_vec(&q).unwrap()).await, StatusCode::OK);

        // Claims must be stamped ~now so the lease is live.
        let now = now_secs();
        let c1 = TaskClaim::create(&w1, &q.id, "t0", now);
        assert_eq!(post_json(&dir, "/claims", serde_json::to_vec(&c1).unwrap()).await, StatusCode::OK);
        // A second worker can't claim the leased task.
        let c2 = TaskClaim::create(&w2, &q.id, "t0", now);
        assert_eq!(
            post_json(&dir, "/claims", serde_json::to_vec(&c2).unwrap()).await,
            StatusCode::CONFLICT
        );
        // But the holder can post a result.
        let r = TaskResult::create(&w1, &q.id, "t0", "answer=42", now);
        assert_eq!(post_json(&dir, "/results", serde_json::to_vec(&r).unwrap()).await, StatusCode::OK);
        // A posted-but-unaccepted result reads "pending" (not yet solved), and
        // the task is no longer "open" (it has a result awaiting acceptance).
        let d = dir.lock().unwrap();
        let state = d.quest_state(&q.id, now).unwrap();
        assert_eq!(state["tasks"][0]["status"], serde_json::json!("pending"));
        assert_eq!(d.open_task_count(&q, now), 0);
    }

    #[tokio::test]
    async fn quest_bounty_escrows_and_pays_on_accept() {
        use revenant_net::quest::{Quest, Task, TaskAccept, TaskResult};
        let dir = shared();
        let mk = || Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
        let (author, worker) = (mk(), mk());
        let aa = { dir.lock().unwrap().acct(&author.id()) };
        let wa = { dir.lock().unwrap().acct(&worker.id()) };

        // A quest staking a 40-credit bounty over 2 tasks (20 each).
        let tasks = vec![
            Task { id: "t0".into(), spec: "a".into(), verify: String::new() },
            Task { id: "t1".into(), spec: "b".into(), verify: String::new() },
        ];
        let q = Quest::create(&author, "solve", "spec", tasks, vec![], 40, 0, 1);
        assert_eq!(post_json(&dir, "/quests", serde_json::to_vec(&q).unwrap()).await, StatusCode::OK);

        // Escrow locked the full 40 out of the author's faucet.
        {
            let d = dir.lock().unwrap();
            let bal = d.credits(now_secs());
            assert_eq!(bal[&aa], FAUCET - 40);
            assert_eq!(*bal.get(&wa).unwrap_or(&FAUCET), FAUCET); // worker untouched
        }

        // Worker solves t0; author accepts → 20 transfers.
        let r = TaskResult::create(&worker, &q.id, "t0", "answer", 2);
        assert_eq!(post_json(&dir, "/results", serde_json::to_vec(&r).unwrap()).await, StatusCode::OK);
        let acc = TaskAccept::create(&author, &q.id, "t0", &r.id, 3);
        assert_eq!(post_json(&dir, "/accept", serde_json::to_vec(&acc).unwrap()).await, StatusCode::OK);
        {
            let d = dir.lock().unwrap();
            let bal = d.credits(now_secs());
            assert_eq!(bal[&wa], FAUCET + 20); // worker paid the t0 share
            assert_eq!(bal[&aa], FAUCET - 40); // author still down 40 (t1 escrow live)
        }
    }

    #[tokio::test]
    async fn quest_bounty_beyond_balance_is_rejected() {
        use revenant_net::quest::{Quest, Task};
        let dir = shared();
        let author = Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
        let tasks = vec![Task { id: "t0".into(), spec: "a".into(), verify: String::new() }];
        // Bounty far exceeds the faucet → 402.
        let q = Quest::create(&author, "greedy", "spec", tasks, vec![], 10_000, 0, 1);
        assert_eq!(
            post_json(&dir, "/quests", serde_json::to_vec(&q).unwrap()).await,
            StatusCode::PAYMENT_REQUIRED
        );
    }

    #[tokio::test]
    async fn quest_trustless_verify_settles_and_pays_cut() {
        use revenant_net::attest::Attestation;
        use revenant_net::quest::{Quest, Task, TaskResult};
        let dir = shared();
        let mk = || Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
        let (author, worker, v1, v2) = (mk(), mk(), mk(), mk());
        // 1 task, bounty 100 → per_task 100; 20% cut → 20 pool, 10 each, solver 80.
        let q = Quest::create(
            &author, "q", "spec",
            vec![Task { id: "t0".into(), spec: "do".into(), verify: "eval".into() }],
            vec![], 100, 0, 1,
        );
        assert_eq!(post_json(&dir, "/quests", serde_json::to_vec(&q).unwrap()).await, StatusCode::OK);
        let r = TaskResult::create(&worker, &q.id, "t0", "answer", 2);
        assert_eq!(post_json(&dir, "/results", serde_json::to_vec(&r).unwrap()).await, StatusCode::OK);

        // The solver can't vouch for their own result.
        let selfv = Attestation::create(&worker, &r.id, true, "", 3);
        assert_eq!(
            post_json(&dir, "/verify", serde_json::to_vec(&selfv).unwrap()).await,
            StatusCode::FORBIDDEN
        );
        // Two independent verifiers reach quorum → the task settles trustlessly.
        for v in [&v1, &v2] {
            let att = Attestation::create(v, &r.id, true, "checked", 3);
            assert_eq!(post_json(&dir, "/verify", serde_json::to_vec(&att).unwrap()).await, StatusCode::OK);
        }
        let d = dir.lock().unwrap();
        let bal = d.credits(now_secs());
        assert_eq!(bal[&worker.id()], FAUCET + 80, "solver gets per_task minus the verifier cut");
        assert_eq!(bal[&v1.id()], FAUCET + 10, "verifier cut split");
        assert_eq!(bal[&v2.id()], FAUCET + 10);
        assert_eq!(bal[&author.id()], FAUCET - 100, "author debited the full task share");
    }

    #[tokio::test]
    async fn boost_burns_credits_and_ranks() {
        use revenant_net::boost::Boost;
        use revenant_net::quest::{Quest, Task};
        let dir = shared();
        let booster = Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
        let ba = { dir.lock().unwrap().acct(&booster.id()) };

        // A quest to boost (no bounty, so escrow doesn't muddy the balance).
        let q = Quest::create(
            &booster, "feature me", "spec",
            vec![Task { id: "t0".into(), spec: "a".into(), verify: String::new() }],
            vec![], 0, 0, 1,
        );
        assert_eq!(post_json(&dir, "/quests", serde_json::to_vec(&q).unwrap()).await, StatusCode::OK);

        // Boost it 30 credits: burned from the booster's balance, added to its score.
        let b = Boost::create(&booster, &q.id, 30, 2);
        assert_eq!(post_json(&dir, "/boost", serde_json::to_vec(&b).unwrap()).await, StatusCode::OK);
        {
            let d = dir.lock().unwrap();
            assert_eq!(d.credits(now_secs())[&ba], FAUCET - 30, "boost burns credits");
            assert_eq!(d.boost_score(&q.id), 30);
        }

        // A boost beyond the remaining balance is refused (402), balance unchanged.
        let broke = Boost::create(&booster, &q.id, 10_000, 3);
        assert_eq!(
            post_json(&dir, "/boost", serde_json::to_vec(&broke).unwrap()).await,
            StatusCode::PAYMENT_REQUIRED
        );
        {
            let d = dir.lock().unwrap();
            assert_eq!(d.credits(now_secs())[&ba], FAUCET - 30, "refused boost didn't debit");
            assert_eq!(d.boost_score(&q.id), 30);
        }
    }

    #[tokio::test]
    async fn quest_close_refunds_escrow_and_leaves_board() {
        use revenant_net::quest::{Quest, QuestClose, Task, TaskAccept, TaskResult};
        let dir = shared();
        let mk = || Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
        let (author, worker) = (mk(), mk());
        let aa = { dir.lock().unwrap().acct(&author.id()) };

        // 2 tasks, 40 bounty (20 each). Author solves/accepts t0, then closes.
        let tasks = vec![
            Task { id: "t0".into(), spec: "a".into(), verify: String::new() },
            Task { id: "t1".into(), spec: "b".into(), verify: String::new() },
        ];
        let q = Quest::create(&author, "closeme", "spec", tasks, vec![], 40, 0, 1);
        assert_eq!(post_json(&dir, "/quests", serde_json::to_vec(&q).unwrap()).await, StatusCode::OK);

        let r = TaskResult::create(&worker, &q.id, "t0", "answer", 2);
        assert_eq!(post_json(&dir, "/results", serde_json::to_vec(&r).unwrap()).await, StatusCode::OK);
        let acc = TaskAccept::create(&author, &q.id, "t0", &r.id, 3);
        assert_eq!(post_json(&dir, "/accept", serde_json::to_vec(&acc).unwrap()).await, StatusCode::OK);

        // Before close: author down the full 40 (20 paid to solver, 20 still escrowed on t1).
        {
            let d = dir.lock().unwrap();
            assert_eq!(d.credits(now_secs())[&aa], FAUCET - 40);
            assert_eq!(d.quest_state(&q.id, now_secs()).unwrap()["status"], serde_json::json!("open"));
        }

        // A non-author can't close it.
        let intruder = mk();
        let bad = QuestClose::create(&intruder, &q.id, 4);
        assert_eq!(
            post_json(&dir, "/close", serde_json::to_vec(&bad).unwrap()).await,
            StatusCode::FORBIDDEN
        );

        // Author closes → the live t1 escrow (20) refunds; only the 20 paid stays spent.
        let close = QuestClose::create(&author, &q.id, 5);
        assert_eq!(post_json(&dir, "/close", serde_json::to_vec(&close).unwrap()).await, StatusCode::OK);
        {
            let d = dir.lock().unwrap();
            assert_eq!(d.credits(now_secs())[&aa], FAUCET - 20, "unsettled escrow refunded on close");
            // t1 never settled → this close is a WITHDRAWAL, not a completion.
            assert_eq!(d.quest_state(&q.id, now_secs()).unwrap()["status"], serde_json::json!("withdrawn"));
            assert!(d.closed.contains_key(&q.id));
        }
        // And it's gone from the board.
        let board = get_json(&dir, "/quests").await;
        assert!(
            board.as_array().unwrap().iter().all(|x| x["id"] != serde_json::json!(q.id)),
            "closed quest must leave the board"
        );
    }

    #[tokio::test]
    async fn close_outcome_is_completed_only_when_every_task_settled() {
        use revenant_net::quest::{Quest, QuestClose, Task, TaskAccept, TaskResult};
        let dir = shared();
        let mk = || Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
        let (author, worker) = (mk(), mk());

        // Single-task quest, actually solved and accepted → closing = completed.
        let q = Quest::create(
            &author, "prove it", "spec",
            vec![Task { id: "t0".into(), spec: "do".into(), verify: String::new() }],
            vec![], 0, 0, 1,
        );
        assert_eq!(post_json(&dir, "/quests", serde_json::to_vec(&q).unwrap()).await, StatusCode::OK);
        let r = TaskResult::create(&worker, &q.id, "t0", "answer", 2);
        assert_eq!(post_json(&dir, "/results", serde_json::to_vec(&r).unwrap()).await, StatusCode::OK);
        let acc = TaskAccept::create(&author, &q.id, "t0", &r.id, 3);
        assert_eq!(post_json(&dir, "/accept", serde_json::to_vec(&acc).unwrap()).await, StatusCode::OK);
        let close = QuestClose::create(&author, &q.id, 4);
        assert_eq!(post_json(&dir, "/close", serde_json::to_vec(&close).unwrap()).await, StatusCode::OK);
        assert_eq!(
            dir.lock().unwrap().quest_state(&q.id, now_secs()).unwrap()["status"],
            serde_json::json!("completed"),
            "a close is 'completed' only when the task was actually settled"
        );

        // Second quest, never solved → closing = withdrawn, not completed.
        let q2 = Quest::create(
            &author, "never done", "spec",
            vec![Task { id: "t0".into(), spec: "do".into(), verify: String::new() }],
            vec![], 0, 0, 5,
        );
        assert_eq!(post_json(&dir, "/quests", serde_json::to_vec(&q2).unwrap()).await, StatusCode::OK);
        let close2 = QuestClose::create(&author, &q2.id, 6);
        assert_eq!(post_json(&dir, "/close", serde_json::to_vec(&close2).unwrap()).await, StatusCode::OK);
        assert_eq!(
            dir.lock().unwrap().quest_state(&q2.id, now_secs()).unwrap()["status"],
            serde_json::json!("withdrawn"),
            "closing an unsolved quest is a withdrawal — proof can't be asserted"
        );
    }

    #[tokio::test]
    async fn horde_board_is_account_private_and_gathers_a_run() {
        use revenant_net::horde::{HordeClaim, HordeResult, HordeTask};
        let dir = shared();
        let mk = || Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
        let (orch, worker, stranger) = (mk(), mk(), mk());
        // orch + worker are two agents of ONE account; stranger is separate.
        {
            let d = dir.lock().unwrap();
            let reg = d.accounts.register("horde@x.com").unwrap();
            d.accounts.verify(&reg.verify_token).unwrap();
            for g in [&orch, &worker] {
                let sig = g.sign_hex(reg.account_key.as_bytes());
                d.accounts.bind(&reg.account_key, &g.id(), &sig).unwrap();
            }
        }
        // Orchestrator posts a subtask under run-1.
        let t = HordeTask::create(&orch, "run-1", "sub A", "do A", vec![], 1);
        assert_eq!(post_json(&dir, "/horde/tasks", serde_json::to_vec(&t).unwrap()).await, StatusCode::OK);

        // Same-account worker sees it; a stranger's board is empty.
        let mine = get_json(&dir, &format!("/horde/tasks?agent={}", worker.id())).await;
        assert_eq!(mine.as_array().unwrap().len(), 1, "same-account worker sees the task");
        let theirs = get_json(&dir, &format!("/horde/tasks?agent={}", stranger.id())).await;
        assert_eq!(theirs.as_array().unwrap().len(), 0, "a stranger can't see the account's board");

        // A stranger can't claim it.
        let sc = HordeClaim::create(&stranger, &t.id, 2);
        assert_eq!(
            post_json(&dir, "/horde/claim", serde_json::to_vec(&sc).unwrap()).await,
            StatusCode::FORBIDDEN
        );

        // Worker claims + submits.
        let c = HordeClaim::create(&worker, &t.id, 2);
        assert_eq!(post_json(&dir, "/horde/claim", serde_json::to_vec(&c).unwrap()).await, StatusCode::OK);
        let r = HordeResult::create(&worker, &t.id, "answer A", 3);
        assert_eq!(post_json(&dir, "/horde/results", serde_json::to_vec(&r).unwrap()).await, StatusCode::OK);

        // The run is complete and the orchestrator gathers the output.
        let run = get_json(&dir, &format!("/horde/runs/run-1?agent={}", orch.id())).await;
        assert_eq!(run["complete"], serde_json::json!(true));
        assert_eq!(run["tasks"][0]["status"], serde_json::json!("solved"));
        assert_eq!(run["tasks"][0]["output"], serde_json::json!("answer A"));
        assert_eq!(run["tasks"][0]["worker"], serde_json::json!(worker.id()));
    }

    #[tokio::test]
    async fn quest_no_self_dealing() {
        use revenant_net::quest::{Quest, Task, TaskClaim, TaskResult};
        let dir = shared();
        let author = Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
        let worker = Identity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
        let q = Quest::create(
            &author, "own quest", "spec",
            vec![Task { id: "t0".into(), spec: "do".into(), verify: String::new() }],
            vec![], 20, 0, 1,
        );
        assert_eq!(post_json(&dir, "/quests", serde_json::to_vec(&q).unwrap()).await, StatusCode::OK);
        let now = now_secs();
        // The author's own account can neither claim nor solve its own quest.
        let c = TaskClaim::create(&author, &q.id, "t0", now);
        assert_eq!(post_json(&dir, "/claims", serde_json::to_vec(&c).unwrap()).await, StatusCode::FORBIDDEN);
        let r = TaskResult::create(&author, &q.id, "t0", "ans", now);
        assert_eq!(post_json(&dir, "/results", serde_json::to_vec(&r).unwrap()).await, StatusCode::FORBIDDEN);
        // A different account is fine.
        let c2 = TaskClaim::create(&worker, &q.id, "t0", now);
        assert_eq!(post_json(&dir, "/claims", serde_json::to_vec(&c2).unwrap()).await, StatusCode::OK);
        // Leaderboard serves.
        let lb = router(dir.clone())
            .oneshot(Request::get("/leaderboard").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(lb.status(), StatusCode::OK);
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

    async fn get_json(dir: &SharedDir, path: &str) -> serde_json::Value {
        let resp = router(dir.clone())
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
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
