//! Ordering and restart-gap behaviour of the host-audit lane.

use std::sync::atomic::AtomicU64;

use super::*;

fn marker_store() -> ScopedKvStore {
    ScopedKvStore::new(
        Arc::new(astrid_storage::MemoryKvStore::new()),
        "system:control:audit-lane",
    )
    .expect("marker scope")
}

/// Wait until the writer has made at least `calls` calls durable.
fn wait_persisted(sink: &KernelAuditSink, calls: u64) {
    let deadline = std::time::Instant::now()
        .checked_add(std::time::Duration::from_secs(10))
        .expect("deadline");
    while sink.health().persisted < calls {
        assert!(std::time::Instant::now() < deadline, "writer stalled");
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

/// Concurrent producers across several principals, with small batches and
/// a short window so many batches interleave with production: every chain
/// lists its calls in exactly the order they were accepted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chain_order_equals_call_order_under_concurrency() {
    let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
    let session = SessionId::from_uuid(uuid::Uuid::from_u128(0x09b1));
    let sink = Arc::new(KernelAuditSink::with_policy(
        Arc::clone(&log),
        session.clone(),
        policy(10, 8, 4096),
    ));
    let principals: Vec<_> = ["alice", "bob", "carol"]
        .iter()
        .map(|name| PrincipalId::new(*name).expect("principal"))
        .collect();
    // The sequence number is drawn in the same critical section as the
    // report, so it is the call order the lane must preserve.
    let order = Arc::new(Mutex::new(()));
    let sequence = Arc::new(AtomicU64::new(0));
    let mut threads = Vec::new();
    for worker in 0..6_usize {
        let sink = Arc::clone(&sink);
        let order = Arc::clone(&order);
        let sequence = Arc::clone(&sequence);
        let principal = principals[worker % principals.len()].clone();
        threads.push(std::thread::spawn(move || {
            for _ in 0..150 {
                let _serial = order.lock().expect("order lock");
                let n = sequence.fetch_add(1, Ordering::SeqCst);
                let path = format!("/seq/{n:06}");
                // Denials are exact entries; every third call is an allowed
                // read between them, recorded as its own one-call run.
                let outcome = if n.is_multiple_of(3) {
                    HostAuditOutcome::Allowed
                } else {
                    HostAuditOutcome::Denied("not in host_fs allowlist")
                };
                sink.record(
                    &principal,
                    HostAuditEvent::FileRead { path: &path },
                    outcome,
                );
            }
        }));
    }
    for thread in threads {
        thread.join().expect("producer");
    }
    sink.shutdown();

    let mut total = 0;
    for principal in &principals {
        let entries = log
            .get_principal_entries(&session, Some(principal))
            .await
            .expect("entries");
        let paths: Vec<String> = entries
            .iter()
            .map(|entry| match &entry.action {
                AuditAction::FileRead { path } => path.clone(),
                AuditAction::HostCallRun { calls } => match &calls.tally[0].first {
                    AuditAction::FileRead { path } => path.clone(),
                    other => panic!("unexpected run sample {other:?}"),
                },
                other => panic!("unexpected action {other:?}"),
            })
            .collect();
        let mut sorted = paths.clone();
        sorted.sort();
        assert_eq!(paths, sorted, "{principal}: chain order must be call order");
        total += entries.len();
        let verification = log
            .verify_principal_chain(&session, Some(principal))
            .await
            .expect("verify");
        assert!(verification.valid, "{verification:?}");
    }
    assert!(total > 0);
    assert_eq!(sink.health().accepted, 900);
    assert_eq!(sink.health().queue_depth, 0);
}

/// A lane run that dies with calls still queued leaves a signed gap entry in
/// every chain it wrote to, and in the system chain, at the next start. A
/// clean shutdown leaves none.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unclean_stop_is_recorded_as_a_gap_at_next_start() {
    let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
    let session = SessionId::from_uuid(uuid::Uuid::from_u128(0x09b2));
    let marker = marker_store();
    let alice = PrincipalId::new("alice").expect("alice");
    let bob = PrincipalId::new("bob").expect("bob");

    let first = KernelAuditSink::with_lane_marker(
        Arc::clone(&log),
        session.clone(),
        policy(10, 128, 4096),
        marker.clone(),
    );
    for principal in [&alice, &bob] {
        first.record(
            principal,
            HostAuditEvent::FileRead { path: "/durable" },
            HostAuditOutcome::Allowed,
        );
    }
    wait_persisted(&first, 2);
    // This call is still queued when the lane run dies.
    first.record(
        &alice,
        HostAuditEvent::FileDelete { path: "/lost" },
        HostAuditOutcome::Denied("not in host_fs allowlist"),
    );
    first.abandon_for_test();
    let before = log.count_session(&session).await.expect("count");

    let second = KernelAuditSink::with_lane_marker(
        Arc::clone(&log),
        session.clone(),
        policy(10, 128, 4096),
        marker.clone(),
    );
    second.shutdown();
    assert_eq!(
        second.health().gaps_recorded,
        3,
        "alice, bob and the system chain"
    );
    for principal in [Some(&alice), Some(&bob), None] {
        let entries = log
            .get_principal_entries(&session, principal)
            .await
            .expect("entries");
        let last = entries.last().expect("gap entry");
        assert!(
            matches!(
                &last.action,
                AuditAction::HostCallGap { reason, .. } if reason == "unclean_shutdown"
            ),
            "{principal:?}: {:?}",
            last.action
        );
    }
    assert_eq!(
        log.count_session(&session).await.expect("count"),
        before + 3
    );
    assert!(log.verify_chain(&session).await.expect("verify").valid);

    // The second run closed cleanly: a third run records no gap.
    let third = KernelAuditSink::with_lane_marker(
        Arc::clone(&log),
        session.clone(),
        policy(10, 128, 4096),
        marker,
    );
    third.shutdown();
    assert_eq!(third.health().gaps_recorded, 0);
    assert_eq!(
        log.count_session(&session).await.expect("count"),
        before + 3
    );
}

/// Gap duties survive a second unclean stop before they were recorded.
#[test]
fn unrecorded_gap_duties_carry_over_to_the_next_run() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime");
    let store = marker_store();
    let (_first, duties) =
        marker::LaneMarker::open(&runtime, store.clone(), "run-1".into(), Timestamp::now())
            .expect("open run 1");
    assert!(duties.is_empty());
    let (mut second, duties) =
        marker::LaneMarker::open(&runtime, store.clone(), "run-2".into(), Timestamp::now())
            .expect("open run 2");
    assert_eq!(duties.len(), 1);
    assert_eq!(duties[0].epoch, "run-1");
    second
        .register(&runtime, &[PrincipalId::new("alice").expect("alice")])
        .expect("register");
    // Run 2 dies before recording run 1's gap.
    let (_third, duties) =
        marker::LaneMarker::open(&runtime, store, "run-3".into(), Timestamp::now())
            .expect("open run 3");
    let epochs: Vec<_> = duties.iter().map(|duty| duty.epoch.as_str()).collect();
    assert_eq!(epochs, ["run-1", "run-2"]);
    assert_eq!(duties[1].chains, ["alice"]);
}

/// Calls reported after shutdown are counted, not queued.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn calls_after_shutdown_are_counted() {
    let log = Arc::new(AuditLog::in_memory(KeyPair::generate()));
    let session = SessionId::from_uuid(uuid::Uuid::from_u128(0x09b5));
    let sink = test_sink(Arc::clone(&log), session);
    let p = principal();
    sink.shutdown();
    sink.record(
        &p,
        HostAuditEvent::FileRead { path: "/late" },
        HostAuditOutcome::Allowed,
    );
    let health = sink.health();
    assert_eq!(health.dropped_after_shutdown, 1);
    assert_eq!(health.accepted, 0);
}
