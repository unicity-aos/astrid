//! Coverage records (HTTP exchanges, tool calls, capsule attribution) in the
//! ordered host-audit lane: committed records keep call order with queued
//! host calls of other capsules, runs and loss tallies keep capsules apart,
//! and HTTP numbering follows the chain and the lane run.

use std::sync::Arc;
use std::time::Duration;

use astrid_audit::host_call::{HostCallOutcome, HostCallRef};
use astrid_audit::{AuditAction, AuditEntry, AuditLog, AuditOutcome, AuthorizationProof};
use astrid_capsule::{
    HostAuditActor, HostAuditEvent, HostAuditOutcome, HostAuditSink, HostHttpRequest,
    HostHttpResponse,
};
use astrid_config::types::AuditConfig;
use astrid_core::{PrincipalId, SessionId, Timestamp};
use astrid_crypto::{ContentHash, KeyPair};
use astrid_storage::ScopedKvStore;

use super::{HostAuditPolicy, KernelAuditSink, coverage};

/// A window long enough that nothing is flushed by time during a test.
const LONG_WINDOW_MS: u64 = 60_000;

fn policy(coalesce_ms: u64, queue_capacity: u64, fail_closed: &[&str]) -> HostAuditPolicy {
    HostAuditPolicy::from(&AuditConfig {
        host_coalesce_ms: coalesce_ms,
        host_queue_capacity: queue_capacity,
        host_fail_closed: fail_closed
            .iter()
            .map(|class| (*class).to_owned())
            .collect(),
        ..AuditConfig::default()
    })
}

fn alice() -> PrincipalId {
    PrincipalId::new("alice").expect("principal")
}

fn host_actor(capsule_id: &str) -> HostAuditActor {
    HostAuditActor {
        capsule_id: capsule_id.to_owned(),
        wasm_hash: Some(ContentHash::hash(capsule_id.as_bytes())),
    }
}

/// The per-capsule handle the engine would get from `attributed`, as the
/// concrete type so tests can pass call times.
fn capsule_handle(sink: &KernelAuditSink, capsule_id: &str) -> KernelAuditSink {
    KernelAuditSink {
        actor: Some(Arc::new(coverage::to_capsule_actor(&host_actor(
            capsule_id,
        )))),
        ..sink.clone()
    }
}

fn request(host: &str) -> HostHttpRequest<'_> {
    HostHttpRequest {
        method: "POST",
        host,
        port: 443,
        path_hash: ContentHash::hash(b"/v1/chat"),
        headers_hash: ContentHash::hash(b"authorization:[REDACTED]\n"),
        body_hash: ContentHash::hash(b"{}"),
        body_len: 2,
        redirect_hop: 0,
        injected_secrets: &[],
    }
}

fn read_action(path: &str, capsule_id: &str) -> AuditAction {
    AuditAction::FileRead {
        path: path.to_owned(),
        actor: Some(coverage::to_capsule_actor(&host_actor(capsule_id))),
    }
}

fn capsule_of(entry: &AuditEntry) -> String {
    entry
        .action
        .actor()
        .map(|actor| actor.capsule_id.clone())
        .unwrap_or_default()
}

fn marker_store() -> ScopedKvStore {
    ScopedKvStore::new(
        Arc::new(astrid_storage::MemoryKvStore::new()),
        "system:control:audit-lane",
    )
    .expect("marker scope")
}

/// `entry` is a run of `capsule` that commits to `calls` (allowed reads).
fn assert_run_of(entry: &AuditEntry, capsule: &str, calls: &[(AuditAction, Timestamp)]) {
    let AuditAction::HostCallRun { calls: run, actor } = &entry.action else {
        panic!("unexpected action {:?}", entry.action);
    };
    assert_eq!(actor.as_ref().map(|a| a.capsule_id.as_str()), Some(capsule));
    let refs: Vec<_> = calls
        .iter()
        .map(|(action, at)| HostCallRef {
            action,
            outcome: HostCallOutcome::Ok,
            detail: "",
            at,
        })
        .collect();
    assert!(run.matches_calls(&refs), "the run commits to its calls");
}

/// A capsule's host calls queued behind the window, then another capsule's
/// HTTP pre-commit on the same chain: the commit returns only once its entry
/// is durable, and the chain holds the run first, then the request, each
/// attributed to its own capsule. The completion links to the request.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn precommit_keeps_call_order_with_a_queued_run_of_another_capsule() {
    let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
    let session = SessionId::from_uuid(uuid::Uuid::from_u128(0x0d01));
    let sink = KernelAuditSink::with_policy(
        Arc::clone(&log),
        session.clone(),
        policy(LONG_WINDOW_MS, 4096, &[]),
    );
    let files = capsule_handle(&sink, "fs-tool");
    let llm = sink.attributed(host_actor("llm")).expect("attributed");
    let p = alice();

    let base = chrono::Utc::now();
    let mut calls = Vec::new();
    for index in 0..3_i64 {
        let at = Timestamp::from_datetime(base + chrono::Duration::microseconds(index));
        let path = format!("/w/{index}");
        files.record_at(
            &p,
            HostAuditEvent::FileRead { path: &path },
            HostAuditOutcome::Allowed,
            at,
        );
        calls.push((read_action(&path, "fs-tool"), at));
    }
    let pre = tokio::time::timeout(
        Duration::from_secs(5),
        llm.commit(
            &p,
            HostAuditEvent::HttpRequest(request("api.example.com")),
            HostAuditOutcome::Allowed,
        ),
    )
    .await
    .expect("the commit does not wait for the window");
    assert_eq!(pre.sequence, Some(1));
    let pre_id = pre.entry_id.clone().expect("durable pre-commit");

    let entries = log.get_principal_entries(&session, Some(&p)).await.unwrap();
    assert_eq!(entries.len(), 2, "the queued run is written first");
    assert_run_of(&entries[0], "fs-tool", &calls);
    assert!(matches!(
        &entries[1].action,
        AuditAction::HttpRequest { sequence: 1, host, .. } if host == "api.example.com"
    ));
    assert_eq!(capsule_of(&entries[1]), "llm");
    assert_eq!(entries[1].id, pre_id);

    files.record(
        &p,
        HostAuditEvent::FileRead { path: "/w/after" },
        HostAuditOutcome::Allowed,
    );
    let ids = [("x-request-id".to_owned(), "req-1".to_owned())];
    let done = llm
        .commit(
            &p,
            HostAuditEvent::HttpResponse(HostHttpResponse {
                request: &pre,
                status: Some(200),
                body_hash: Some(ContentHash::hash(b"ok")),
                body_len: 2,
                complete: true,
                provider_request_ids: &ids,
            }),
            HostAuditOutcome::Allowed,
        )
        .await;
    assert!(done.entry_id.is_some());
    sink.shutdown();

    let entries = log.get_principal_entries(&session, Some(&p)).await.unwrap();
    let shape: Vec<_> = entries
        .iter()
        .map(|entry| (entry.action.description(), capsule_of(entry)))
        .collect();
    assert_eq!(
        shape,
        [
            (
                "Recorded 3 host calls of fs-tool".to_owned(),
                "fs-tool".to_owned()
            ),
            (
                "HTTP request #1 POST api.example.com:443".to_owned(),
                "llm".to_owned()
            ),
            ("Read file /w/after".to_owned(), "fs-tool".to_owned()),
            ("HTTP response #1 status 200".to_owned(), "llm".to_owned()),
        ]
    );
    assert!(matches!(
        &entries[3].action,
        AuditAction::HttpResponse { request_entry_id: Some(id), provider_request_ids, .. }
            if *id == pre_id && provider_request_ids.len() == 1
    ));
    assert!(log.verify_chain(&session).await.expect("verify").valid);
}

/// Fill a 64-slot queue with distinct denials of `files`, then report four
/// records over capacity: a denied read of `files`, a denied HTTP request and
/// a failed tool call of `llm`, and one more denied read of `files`.
fn overflow_the_queue(
    files: &KernelAuditSink,
    llm: &KernelAuditSink,
    p: &PrincipalId,
    at: impl Fn(i64) -> Timestamp,
) {
    for index in 0..64_i64 {
        files.record_at(
            p,
            HostAuditEvent::FileRead {
                path: &format!("/denied-{index}"),
            },
            HostAuditOutcome::Denied("not in host_fs allowlist"),
            at(index),
        );
    }
    files.record_at(
        p,
        HostAuditEvent::FileRead { path: "/lost-0" },
        HostAuditOutcome::Denied("not in host_fs allowlist"),
        at(64),
    );
    llm.record_at(
        p,
        HostAuditEvent::HttpRequest(request("blocked.example.com")),
        HostAuditOutcome::Denied("egress denied"),
        at(65),
    );
    llm.record_at(
        p,
        HostAuditEvent::ToolCall {
            capsule_id: "llm",
            tool: "search",
            call_id: Some("call-1"),
            args_hash: ContentHash::hash(b"{}"),
            result_hash: None,
        },
        HostAuditOutcome::Failed("no result published"),
        at(66),
    );
    files.record_at(
        p,
        HostAuditEvent::FileRead { path: "/lost-1" },
        HostAuditOutcome::Denied("not in host_fs allowlist"),
        at(67),
    );
}

/// The loss entry of [`overflow_the_queue`]: one tally per class, outcome
/// and capsule, and a fold over the four records in call order.
fn assert_loss_commits_to_the_lost_records(entry: &AuditEntry, at: impl Fn(i64) -> Timestamp) {
    let AuditAction::HostCallLoss { calls, reason } = &entry.action else {
        panic!("unexpected action {:?}", entry.action);
    };
    assert_eq!(reason, "queue_full");
    assert_eq!(calls.count, 4);
    let tallies: Vec<_> = calls
        .tally
        .iter()
        .map(|tally| {
            (
                tally.class.as_str(),
                tally.outcome,
                tally.count,
                tally.first.actor().map(|a| a.capsule_id.as_str()),
            )
        })
        .collect();
    assert_eq!(
        tallies,
        [
            ("file_read", HostCallOutcome::Denied, 2, Some("fs-tool")),
            ("http_request", HostCallOutcome::Denied, 1, Some("llm")),
            ("capsule_tool_call", HostCallOutcome::Failed, 1, Some("llm")),
        ]
    );
    let lost_http = calls.tally[1].first.clone();
    assert!(matches!(
        &lost_http,
        AuditAction::HttpRequest { sequence: 1, .. }
    ));
    let denied = "not in host_fs allowlist";
    let lost = [
        (
            read_action("/lost-0", "fs-tool"),
            HostCallOutcome::Denied,
            denied,
            at(64),
        ),
        (lost_http, HostCallOutcome::Denied, "egress denied", at(65)),
        (
            calls.tally[2].first.clone(),
            HostCallOutcome::Failed,
            "no result published",
            at(66),
        ),
        (
            read_action("/lost-1", "fs-tool"),
            HostCallOutcome::Denied,
            denied,
            at(67),
        ),
    ];
    let refs: Vec<_> = lost
        .iter()
        .map(|(action, outcome, detail, at)| HostCallRef {
            action,
            outcome: *outcome,
            detail,
            at,
        })
        .collect();
    assert!(
        calls.matches_calls(&refs),
        "the fold commits to every record"
    );
}

/// With the queue full, records that are not host calls are counted in the
/// chain's loss entry like host calls, one tally per class, outcome and
/// capsule, and the fold commits to them. A committed record is never lost to
/// a full queue: it is written after the loss entry, in call order.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_queue_counts_records_per_capsule_and_never_drops_a_commit() {
    let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
    let session = SessionId::from_uuid(uuid::Uuid::from_u128(0x0d02));
    let sink = KernelAuditSink::with_policy(
        Arc::clone(&log),
        session.clone(),
        policy(LONG_WINDOW_MS, 64, &[]),
    );
    let files = capsule_handle(&sink, "fs-tool");
    let llm = capsule_handle(&sink, "llm");
    let p = alice();
    let base = chrono::Utc::now();
    let at = |index: i64| Timestamp::from_datetime(base + chrono::Duration::microseconds(index));

    overflow_the_queue(&files, &llm, &p, at);
    assert_eq!(sink.health().queue_full, 4);

    let committed = llm
        .commit(
            &p,
            HostAuditEvent::HttpRequest(request("api.example.com")),
            HostAuditOutcome::Allowed,
        )
        .await;
    assert_eq!(committed.sequence, Some(2), "the denied request took 1");
    assert!(committed.entry_id.is_some(), "a commit is never lost");
    sink.shutdown();

    let entries = log.get_principal_entries(&session, Some(&p)).await.unwrap();
    assert_eq!(entries.len(), 66, "64 denials, one loss entry, the commit");
    assert_loss_commits_to_the_lost_records(&entries[64], at);
    assert!(matches!(
        &entries[65].action,
        AuditAction::HttpRequest { sequence: 2, host, .. } if host == "api.example.com"
    ));
    assert!(log.verify_chain(&session).await.expect("verify").valid);
}

/// A commit whose batch the log refuses returns without an entry id after the
/// first failed attempt instead of waiting out the retries; the record stays
/// queued and is written in its place once the log accepts it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_commit_returns_early_and_is_written_once_the_log_recovers() {
    let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
    let session = SessionId::from_uuid(uuid::Uuid::from_u128(0x0d03));
    let p = alice();
    log.set_global_retention_caps(1, u64::MAX)
        .await
        .expect("caps");
    log.append_with_principal(
        session.clone(),
        p.clone(),
        AuditAction::ConfigReloaded,
        AuthorizationProof::System {
            reason: "test".into(),
        },
        AuditOutcome::success(),
    )
    .await
    .expect("first entry");
    let sink = KernelAuditSink::with_policy(
        Arc::clone(&log),
        session.clone(),
        policy(LONG_WINDOW_MS, 4096, &[]),
    );
    let llm = sink.attributed(host_actor("llm")).expect("attributed");

    let started = std::time::Instant::now();
    let receipt = llm
        .commit(
            &p,
            HostAuditEvent::HttpRequest(request("api.example.com")),
            HostAuditOutcome::Allowed,
        )
        .await;
    assert!(started.elapsed() < Duration::from_secs(5), "answered early");
    assert_eq!(receipt.sequence, Some(1));
    assert!(receipt.entry_id.is_none(), "not durable yet");
    assert!(sink.health().failed > 0);

    log.set_global_retention_caps(1_000, u64::MAX)
        .await
        .expect("raise caps");
    let deadline = std::time::Instant::now()
        .checked_add(Duration::from_secs(10))
        .expect("deadline");
    while sink.health().persisted < 1 {
        assert!(std::time::Instant::now() < deadline, "writer stalled");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    sink.shutdown();

    let entries = log.get_principal_entries(&session, Some(&p)).await.unwrap();
    assert_eq!(entries.len(), 2);
    assert!(matches!(
        &entries[1].action,
        AuditAction::HttpRequest { sequence: 1, .. }
    ));
    assert_eq!(capsule_of(&entries[1]), "llm");
    assert!(log.verify_chain(&session).await.expect("verify").valid);
}

/// The per-capsule handle keeps the operator's fail-closed policy: its write
/// waits for a durable write-ahead entry that names the capsule and the
/// content hash, before the outcome.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn attributed_handle_admits_fail_closed_calls_with_their_capsule() {
    let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
    let session = SessionId::from_uuid(uuid::Uuid::from_u128(0x0d04));
    let sink = KernelAuditSink::with_policy(
        Arc::clone(&log),
        session.clone(),
        policy(LONG_WINDOW_MS, 4096, &["file_write"]),
    );
    let writer = sink.attributed(host_actor("writer")).expect("attributed");
    let p = alice();
    let hash = ContentHash::hash(b"hi");
    let event = HostAuditEvent::FileWrite {
        path: "/w/hello.txt",
        content_hash: Some(hash),
    };

    writer.admit(&p, event).expect("durable admission");
    let entries = log.get_principal_entries(&session, Some(&p)).await.unwrap();
    assert_eq!(entries.len(), 1, "durable before the effect");
    let AuditAction::HostCallAdmitted { call } = &entries[0].action else {
        panic!("unexpected action {:?}", entries[0].action);
    };
    assert!(matches!(
        call.as_ref(),
        AuditAction::FileWrite { path, content_hash, actor: Some(actor) }
            if path == "/w/hello.txt" && *content_hash == hash && actor.capsule_id == "writer"
    ));
    assert_eq!(capsule_of(&entries[0]), "writer");

    writer.record(&p, event, HostAuditOutcome::Allowed);
    sink.shutdown();
    let entries = log.get_principal_entries(&session, Some(&p)).await.unwrap();
    assert_eq!(entries.len(), 2);
    assert!(matches!(
        &entries[1].action,
        AuditAction::FileWrite { content_hash, actor: Some(actor), .. }
            if *content_hash == hash && actor.capsule_id == "writer"
    ));
}

/// Concurrent HTTP requests of several capsules on one chain take their
/// numbers in chain order.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_sequence_increases_along_the_chain() {
    let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
    let session = SessionId::from_uuid(uuid::Uuid::from_u128(0x0d05));
    let sink =
        KernelAuditSink::with_policy(Arc::clone(&log), session.clone(), policy(10, 4096, &[]));
    let p = alice();
    let mut tasks = Vec::new();
    for capsule in 0..4 {
        let handle = sink
            .attributed(host_actor(&format!("capsule-{capsule}")))
            .expect("attributed");
        let p = p.clone();
        tasks.push(tokio::spawn(async move {
            for index in 0..10 {
                let outcome = if index % 3 == 0 {
                    HostAuditOutcome::Denied("egress denied")
                } else {
                    HostAuditOutcome::Allowed
                };
                if index % 3 == 0 {
                    handle.record(
                        &p,
                        HostAuditEvent::HttpRequest(request("api.example.com")),
                        outcome,
                    );
                } else {
                    handle
                        .commit(
                            &p,
                            HostAuditEvent::HttpRequest(request("api.example.com")),
                            outcome,
                        )
                        .await;
                }
            }
        }));
    }
    for task in tasks {
        task.await.expect("task");
    }
    sink.shutdown();

    let sequences: Vec<u64> = log
        .get_principal_entries(&session, Some(&p))
        .await
        .unwrap()
        .iter()
        .map(|entry| match &entry.action {
            AuditAction::HttpRequest { sequence, .. } => *sequence,
            other => panic!("unexpected action {other:?}"),
        })
        .collect();
    assert_eq!(sequences, (1..=40).collect::<Vec<_>>());
}

/// HTTP entries carry the lane run's epoch as their run id, so the gap entry
/// a stopped run leaves names the run whose numbering may be cut short; the
/// next run numbers from 1 under a new id.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_run_id_is_the_lane_epoch_a_gap_names() {
    let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
    let session = SessionId::from_uuid(uuid::Uuid::from_u128(0x0d06));
    let marker = marker_store();
    let p = alice();

    let first = KernelAuditSink::with_lane_marker(
        Arc::clone(&log),
        session.clone(),
        policy(LONG_WINDOW_MS, 4096, &[]),
        marker.clone(),
    );
    let llm = first.attributed(host_actor("llm")).expect("attributed");
    let receipt = llm
        .commit(
            &p,
            HostAuditEvent::HttpRequest(request("api.example.com")),
            HostAuditOutcome::Allowed,
        )
        .await;
    assert!(receipt.entry_id.is_some());
    llm.record(
        &p,
        HostAuditEvent::HttpRequest(request("blocked.example.com")),
        HostAuditOutcome::Denied("egress denied"),
    );
    first.abandon_for_test();

    let second = KernelAuditSink::with_lane_marker(
        Arc::clone(&log),
        session.clone(),
        policy(10, 4096, &[]),
        marker,
    );
    let receipt = second
        .attributed(host_actor("llm"))
        .expect("attributed")
        .commit(
            &p,
            HostAuditEvent::HttpRequest(request("api.example.com")),
            HostAuditOutcome::Allowed,
        )
        .await;
    assert_eq!(receipt.sequence, Some(1), "numbering restarts per run");
    second.shutdown();

    let entries = log.get_principal_entries(&session, Some(&p)).await.unwrap();
    let run_of = |entry: &AuditEntry| match &entry.action {
        AuditAction::HttpRequest {
            run_id, sequence, ..
        } => (run_id.clone(), *sequence),
        other => panic!("unexpected action {other:?}"),
    };
    assert_eq!(entries.len(), 3, "request, gap, request");
    let (first_run, first_sequence) = run_of(&entries[0]);
    assert_eq!(first_sequence, 1);
    let AuditAction::HostCallGap { epoch, reason, .. } = &entries[1].action else {
        panic!("unexpected action {:?}", entries[1].action);
    };
    assert_eq!(reason, "unclean_shutdown");
    assert_eq!(*epoch, first_run, "the gap names the run");
    let (second_run, second_sequence) = run_of(&entries[2]);
    assert_eq!(second_sequence, 1);
    assert_ne!(second_run, first_run);
    assert!(log.verify_chain(&session).await.expect("verify").valid);
}

/// A record committed after the writer stopped is still durable before the
/// caller continues: it is appended directly, after everything the drained
/// lane wrote.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commit_after_shutdown_is_appended_directly() {
    let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
    let session = SessionId::from_uuid(uuid::Uuid::from_u128(0x0d07));
    let sink = KernelAuditSink::with_policy(
        Arc::clone(&log),
        session.clone(),
        policy(LONG_WINDOW_MS, 4096, &[]),
    );
    let files = sink.attributed(host_actor("fs-tool")).expect("attributed");
    let llm = sink.attributed(host_actor("llm")).expect("attributed");
    let p = alice();
    for path in ["/w/a", "/w/b"] {
        files.record(
            &p,
            HostAuditEvent::FileRead { path },
            HostAuditOutcome::Allowed,
        );
    }
    sink.shutdown();

    let receipt = llm
        .commit(
            &p,
            HostAuditEvent::HttpRequest(request("api.example.com")),
            HostAuditOutcome::Allowed,
        )
        .await;
    assert_eq!(receipt.sequence, Some(1));
    let entries = log.get_principal_entries(&session, Some(&p)).await.unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(receipt.entry_id, Some(entries[1].id.clone()));
    assert!(matches!(
        &entries[0].action,
        AuditAction::HostCallRun { calls, .. } if calls.count == 2
    ));
    assert!(matches!(
        &entries[1].action,
        AuditAction::HttpRequest { sequence: 1, .. }
    ));
    assert_eq!(capsule_of(&entries[1]), "llm");
    assert_eq!(sink.health().dropped_after_shutdown, 0);
    assert!(log.verify_chain(&session).await.expect("verify").valid);
}

/// Records committed concurrently after the lane drained keep call order:
/// numbering and the direct append happen under one lock.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn direct_commits_after_shutdown_keep_call_order() {
    let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
    let session = SessionId::from_uuid(uuid::Uuid::from_u128(0x0d08));
    let sink =
        KernelAuditSink::with_policy(Arc::clone(&log), session.clone(), policy(10, 4096, &[]));
    sink.shutdown();
    let p = alice();
    let mut tasks = Vec::new();
    for capsule in 0..4 {
        let handle = sink
            .attributed(host_actor(&format!("capsule-{capsule}")))
            .expect("attributed");
        let p = p.clone();
        tasks.push(tokio::spawn(async move {
            for _ in 0..5 {
                let receipt = handle
                    .commit(
                        &p,
                        HostAuditEvent::HttpRequest(request("api.example.com")),
                        HostAuditOutcome::Allowed,
                    )
                    .await;
                assert!(receipt.entry_id.is_some());
            }
        }));
    }
    for task in tasks {
        task.await.expect("task");
    }
    let sequences: Vec<u64> = log
        .get_principal_entries(&session, Some(&p))
        .await
        .unwrap()
        .iter()
        .map(|entry| match &entry.action {
            AuditAction::HttpRequest { sequence, .. } => *sequence,
            other => panic!("unexpected action {other:?}"),
        })
        .collect();
    assert_eq!(sequences, (1..=20).collect::<Vec<_>>());
}

/// After the writer stopped without draining, a committed record is not
/// appended behind the lost queue: the caller continues without an entry id,
/// and the next start's gap entry is the next entry on the chain.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commit_after_an_unclean_stop_is_left_to_the_gap() {
    let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
    let session = SessionId::from_uuid(uuid::Uuid::from_u128(0x0d09));
    let marker = marker_store();
    let p = alice();
    let first = KernelAuditSink::with_lane_marker(
        Arc::clone(&log),
        session.clone(),
        policy(LONG_WINDOW_MS, 4096, &[]),
        marker.clone(),
    );
    let llm = first.attributed(host_actor("llm")).expect("attributed");
    let durable = llm
        .commit(
            &p,
            HostAuditEvent::HttpRequest(request("api.example.com")),
            HostAuditOutcome::Allowed,
        )
        .await;
    assert!(durable.entry_id.is_some());
    llm.record(
        &p,
        HostAuditEvent::FileRead { path: "/queued" },
        HostAuditOutcome::Allowed,
    );
    first.abandon_for_test();

    let late = llm
        .commit(
            &p,
            HostAuditEvent::HttpRequest(request("api.example.com")),
            HostAuditOutcome::Allowed,
        )
        .await;
    assert_eq!(late.sequence, Some(2), "the number is consumed");
    assert!(
        late.entry_id.is_none(),
        "not appended behind the lost queue"
    );
    assert_eq!(first.health().dropped_after_shutdown, 1);

    let second = KernelAuditSink::with_lane_marker(
        Arc::clone(&log),
        session.clone(),
        policy(10, 4096, &[]),
        marker,
    );
    second.shutdown();
    let entries = log.get_principal_entries(&session, Some(&p)).await.unwrap();
    assert_eq!(entries.len(), 2, "request, then the gap");
    assert!(matches!(
        &entries[0].action,
        AuditAction::HttpRequest { sequence: 1, .. }
    ));
    assert!(matches!(
        &entries[1].action,
        AuditAction::HostCallGap { reason, .. } if reason == "unclean_shutdown"
    ));
}
