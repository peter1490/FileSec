//! End-to-end loopback tests for the direct-transfer net layer: a real listener
//! and sender, on dedicated threads, over `127.0.0.1`. Exercises the wire framing,
//! the listener/sender state machines, the contact-book gate, the pairing code,
//! and the verify-and-import path — without a window or a real network.
#![cfg(feature = "net")]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use filesec_core::contacts::{ContactBook, Trust};
use filesec_core::identity::Identity;
use filesec_core::vault::Vault;
use filesec_gui::net::{self, ListenConfig, NetCommand, NetEvent, NetHandle, SendConfig};
use filesec_gui::store::{new_vault_id, Store};

fn tmp(tag: &str) -> PathBuf {
    let suffix = filesec_core::util::hex(&filesec_core::secret::random_vec(8).unwrap());
    std::env::temp_dir().join(format!("filesec-net-{tag}-{suffix}"))
}

/// Drain events until one satisfies `pred` or `timeout` elapses.
fn recv_until(
    handle: &NetHandle,
    timeout: Duration,
    pred: impl Fn(&NetEvent) -> bool,
) -> Option<NetEvent> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(event) = handle.try_recv() {
            if pred(&event) {
                return Some(event);
            }
        } else if Instant::now() >= deadline {
            return None;
        } else {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

/// Set up a sender store holding one vault and a receiver store, plus the two
/// identities. Returns `(alice, bob, send_store, recv_store, vault_id)`.
fn fixture() -> (Arc<Identity>, Arc<Identity>, Arc<Store>, Arc<Store>, String) {
    let send_store = Arc::new(Store::at(tmp("send")).unwrap());
    let recv_store = Arc::new(Store::at(tmp("recv")).unwrap());
    let alice = Arc::new(Identity::generate("Alice", 0).unwrap());
    let bob = Arc::new(Identity::generate("Bob", 0).unwrap());

    let vid = new_vault_id();
    let mut vault = Vault::new("Shared", 0);
    vault
        .add_file(
            "notes/hello.txt",
            b"hello over the wire".to_vec(),
            None,
            None,
        )
        .unwrap();
    send_store.save_vault(&alice, &vid, &vault).unwrap();

    (alice, bob, send_store, recv_store, vid)
}

/// Start Bob listening (designating `expected` as the sender) and return his
/// handle plus the chosen port and pairing code.
fn start_bob(
    bob: Arc<Identity>,
    store: Arc<Store>,
    contacts: ContactBook,
    expected: Option<[u8; 32]>,
) -> (NetHandle, u16, String) {
    let ctx = egui::Context::default();
    let handle = net::start_listener(
        ListenConfig {
            port: 0,
            internet: false,
            expected_sender_fpr: expected,
        },
        bob,
        store,
        contacts,
        ctx,
    );
    let event = recv_until(&handle, Duration::from_secs(5), |e| {
        matches!(e, NetEvent::Listening { .. })
    })
    .expect("listener should come up");
    let (lan_addr, code) = match event {
        NetEvent::Listening {
            lan_addr,
            pairing_code,
            ..
        } => (lan_addr, pairing_code),
        other => panic!("expected Listening, got {other:?}"),
    };
    let port = lan_addr
        .rsplit(':')
        .next()
        .and_then(|p| p.parse::<u16>().ok())
        .expect("a port in the listen address");
    (handle, port, code)
}

#[test]
fn loopback_transfer_imports_the_vault() {
    let (alice, bob, send_store, recv_store, vid) = fixture();

    // Bob trusts Alice (verified contact).
    let mut contacts = ContactBook::default();
    contacts.upsert(alice.public(), 0);
    contacts.set_trust(&alice.fingerprint(), Trust::Verified, 0);

    let (mut bob_h, port, code) = start_bob(
        bob.clone(),
        recv_store.clone(),
        contacts,
        Some(alice.fingerprint()),
    );

    let mut alice_h = net::start_sender(
        SendConfig {
            host: "127.0.0.1".into(),
            port,
            recipient: bob.public(),
            recipient_fpr: bob.fingerprint(),
            pairing_code: Some(code),
            vault_id: vid,
        },
        alice.clone(),
        send_store,
        egui::Context::default(),
    );

    // Bob is offered the transfer and accepts it.
    let offer = recv_until(&bob_h, Duration::from_secs(10), |e| {
        matches!(e, NetEvent::Offer { .. })
    })
    .expect("an offer should arrive");
    if let NetEvent::Offer { verified, size, .. } = offer {
        assert!(verified, "the sender must be a verified contact");
        assert!(size > 0);
    }
    bob_h.send(NetCommand::AcceptOffer);

    // Bob receives and imports the vault.
    let meta = match recv_until(&bob_h, Duration::from_secs(20), |e| {
        matches!(e, NetEvent::Received { .. })
    }) {
        Some(NetEvent::Received { meta, .. }) => meta,
        other => panic!("expected Received, got {other:?}"),
    };
    assert_eq!(meta.name, "Shared");

    // The imported content matches what Alice sent.
    let reader = recv_store.open_vault(&bob, &meta.id).unwrap();
    let bytes = reader.read_entry("notes/hello.txt").unwrap();
    assert_eq!(&bytes[..], b"hello over the wire");

    bob_h.stop();
    alice_h.stop();
}

#[test]
fn loopback_rejects_unverified_sender() {
    let (alice, bob, send_store, recv_store, vid) = fixture();

    // Bob knows Alice but has NOT verified her.
    let mut contacts = ContactBook::default();
    contacts.upsert(alice.public(), 0); // stays Unverified

    let (mut bob_h, port, code) =
        start_bob(bob.clone(), recv_store, contacts, Some(alice.fingerprint()));

    let mut alice_h = net::start_sender(
        SendConfig {
            host: "127.0.0.1".into(),
            port,
            recipient: bob.public(),
            recipient_fpr: bob.fingerprint(),
            pairing_code: Some(code),
            vault_id: vid,
        },
        alice,
        send_store,
        egui::Context::default(),
    );

    // The receiver must refuse with an error and never import.
    let event = recv_until(&bob_h, Duration::from_secs(10), |e| {
        matches!(e, NetEvent::Received { .. } | NetEvent::Error(_))
    })
    .expect("an outcome should arrive");
    assert!(
        matches!(event, NetEvent::Error(_)),
        "an unverified sender must be refused, got {event:?}"
    );

    bob_h.stop();
    alice_h.stop();
}

#[test]
fn loopback_rejects_a_non_designated_sender() {
    let (alice, bob, send_store, recv_store, vid) = fixture();
    let carol = Arc::new(Identity::generate("Carol", 9).unwrap());

    // Bob has verified Alice, but he designates Carol as the expected sender.
    let mut contacts = ContactBook::default();
    contacts.upsert(alice.public(), 0);
    contacts.set_trust(&alice.fingerprint(), Trust::Verified, 0);

    let (mut bob_h, port, code) =
        start_bob(bob.clone(), recv_store, contacts, Some(carol.fingerprint()));

    // Alice (a verified contact, but not the one Bob designated) connects.
    let mut alice_h = net::start_sender(
        SendConfig {
            host: "127.0.0.1".into(),
            port,
            recipient: bob.public(),
            recipient_fpr: bob.fingerprint(),
            pairing_code: Some(code),
            vault_id: vid,
        },
        alice,
        send_store,
        egui::Context::default(),
    );

    let event = recv_until(&bob_h, Duration::from_secs(10), |e| {
        matches!(e, NetEvent::Received { .. } | NetEvent::Error(_))
    })
    .expect("an outcome should arrive");
    assert!(
        matches!(event, NetEvent::Error(_)),
        "a non-designated sender must be refused, got {event:?}"
    );

    bob_h.stop();
    alice_h.stop();
}

#[test]
fn loopback_wrong_pairing_code_aborts() {
    let (alice, bob, send_store, recv_store, vid) = fixture();

    let mut contacts = ContactBook::default();
    contacts.upsert(alice.public(), 0);
    contacts.set_trust(&alice.fingerprint(), Trust::Verified, 0);

    let (mut bob_h, port, _code) =
        start_bob(bob.clone(), recv_store, contacts, Some(alice.fingerprint()));

    // Alice supplies the wrong code.
    let mut alice_h = net::start_sender(
        SendConfig {
            host: "127.0.0.1".into(),
            port,
            recipient: bob.public(),
            recipient_fpr: bob.fingerprint(),
            pairing_code: Some("00000000".into()),
            vault_id: vid,
        },
        alice,
        send_store,
        egui::Context::default(),
    );

    // The sender's handshake must fail (pairing-code mismatch); no import happens.
    let sender_event = recv_until(&alice_h, Duration::from_secs(10), |e| {
        matches!(e, NetEvent::Error(_) | NetEvent::Sent { .. })
    })
    .expect("the sender should report an outcome");
    assert!(
        matches!(sender_event, NetEvent::Error(_)),
        "a wrong pairing code must abort, got {sender_event:?}"
    );

    let received = recv_until(&bob_h, Duration::from_secs(2), |e| {
        matches!(e, NetEvent::Received { .. })
    });
    assert!(
        received.is_none(),
        "nothing should be imported on a bad code"
    );

    bob_h.stop();
    alice_h.stop();
}
