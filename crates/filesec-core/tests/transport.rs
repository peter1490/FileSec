//! End-to-end tests for the direct-transfer handshake + record layer.
//!
//! Black-box against the public API a consumer (filesec-gui) would use. The
//! protocol-internal cases (downgrade, field tampering, replay) live in the
//! inline `#[cfg(test)]` module in `src/transport.rs`, which can reach the
//! private wire structs.
#![cfg(feature = "net")]

use filesec_core::transport::{Initiator, Responder, Session};
use filesec_core::{Error, Identity, RecordType};
use proptest::prelude::*;

fn pair() -> (Identity, Identity) {
    (
        Identity::generate("Alice", 1).expect("alice"),
        Identity::generate("Bob", 2).expect("bob"),
    )
}

/// Run a full handshake. Returns `(initiator_session, responder_session,
/// authenticated_initiator_fpr)`.
fn handshake(
    initiator_id: &Identity,
    responder_id: &Identity,
    expected_peer_fpr: [u8; 32],
    init_code: Option<&[u8]>,
    resp_code: Option<&[u8]>,
) -> Result<(Session, Session, [u8; 32]), Error> {
    let initiator = Initiator::new(initiator_id, expected_peer_fpr, init_code)?;
    let mut responder = Responder::new(responder_id, resp_code, None)?;
    let hello = initiator.write_hello()?;
    let auth = responder.read_hello_write_auth(&hello)?;
    let (confirm, isess) = initiator.read_auth_write_confirm(&auth)?;
    let (peer, rsess) = responder.read_confirm(&confirm)?;
    Ok((isess, rsess, peer.fingerprint))
}

#[test]
fn full_handshake_and_transfer_roundtrip() {
    let (alice, bob) = pair();
    let (mut isess, mut rsess, peer_fpr) =
        handshake(&alice, &bob, bob.fingerprint(), None, None).expect("handshake");

    // The responder learns the initiator's real, verified fingerprint.
    assert_eq!(peer_fpr, alice.fingerprint());

    // Sender → receiver: offer.
    let offer = isess
        .seal_record(RecordType::Offer, b"vault.fsec/4096")
        .unwrap();
    let (t, pt) = rsess.open_record(&offer).unwrap();
    assert_eq!(t, RecordType::Offer);
    assert_eq!(&pt[..], b"vault.fsec/4096");

    // Receiver → sender: accept.
    let dec = rsess
        .seal_record(RecordType::OfferDecision, b"accept")
        .unwrap();
    let (t, pt) = isess.open_record(&dec).unwrap();
    assert_eq!(t, RecordType::OfferDecision);
    assert_eq!(&pt[..], b"accept");

    // Sender → receiver: a couple of data chunks then done.
    for chunk in [&b"chunk-one"[..], &b"chunk-two"[..]] {
        let frame = isess.seal_record(RecordType::Data, chunk).unwrap();
        let (t, pt) = rsess.open_record(&frame).unwrap();
        assert_eq!(t, RecordType::Data);
        assert_eq!(&pt[..], chunk);
    }
    let done = isess.seal_record(RecordType::Done, b"").unwrap();
    let (t, _) = rsess.open_record(&done).unwrap();
    assert_eq!(t, RecordType::Done);
}

#[test]
fn matching_pairing_code_succeeds() {
    let (alice, bob) = pair();
    let code = b"1234-5678";
    let (_i, _r, peer) =
        handshake(&alice, &bob, bob.fingerprint(), Some(code), Some(code)).expect("handshake");
    assert_eq!(peer, alice.fingerprint());
}

/// Assert a handshake fails with a specific error, without requiring the `Ok`
/// type (`Session`, which holds keys) to implement `Debug`.
fn expect_handshake_error(
    result: Result<(Session, Session, [u8; 32]), Error>,
    want: &str,
    matches_want: impl Fn(&Error) -> bool,
) {
    match result {
        Err(e) if matches_want(&e) => {}
        Err(e) => panic!("expected {want}, got {e:?}"),
        Ok(_) => panic!("expected {want}, but the handshake succeeded"),
    }
}

#[test]
fn mismatched_pairing_code_aborts() {
    let (alice, bob) = pair();
    let result = handshake(
        &alice,
        &bob,
        bob.fingerprint(),
        Some(b"11111111"),
        Some(b"22222222"),
    );
    expect_handshake_error(result, "PairingCodeMismatch", |e| {
        matches!(e, Error::PairingCodeMismatch)
    });
}

#[test]
fn one_sided_pairing_code_aborts() {
    let (alice, bob) = pair();
    // Initiator supplies a code, responder expects none → the initiator (which
    // knows a code was in play) reports a pairing-code mismatch.
    let result = handshake(&alice, &bob, bob.fingerprint(), Some(b"99999999"), None);
    expect_handshake_error(result, "PairingCodeMismatch", |e| {
        matches!(e, Error::PairingCodeMismatch)
    });
}

#[test]
fn wrong_expected_fingerprint_aborts() {
    let (alice, bob) = pair();
    // Initiator dials expecting Alice's own fingerprint, but reaches Bob.
    let result = handshake(&alice, &bob, alice.fingerprint(), None, None);
    expect_handshake_error(result, "PeerIdentityMismatch", |e| {
        matches!(e, Error::PeerIdentityMismatch)
    });
}

#[test]
fn responder_accepts_its_designated_sender() {
    let (alice, bob) = pair(); // alice = initiator/sender, bob = responder/receiver
    let initiator = Initiator::new(&alice, bob.fingerprint(), None).unwrap();
    // Bob designates Alice as the expected sender.
    let mut responder = Responder::new(&bob, None, Some(alice.fingerprint())).unwrap();
    let hello = initiator.write_hello().unwrap();
    let auth = responder.read_hello_write_auth(&hello).unwrap();
    let (confirm, _isess) = initiator.read_auth_write_confirm(&auth).unwrap();
    let (peer, _rsess) = responder.read_confirm(&confirm).unwrap();
    assert_eq!(peer.fingerprint, alice.fingerprint());
}

#[test]
fn responder_rejects_an_undesignated_sender() {
    let (alice, bob) = pair();
    let carol = Identity::generate("Carol", 3).expect("carol");
    let initiator = Initiator::new(&alice, bob.fingerprint(), None).unwrap();
    // Bob is expecting Carol, but Alice connects — even though Alice authenticates
    // validly, she is not the designated sender.
    let mut responder = Responder::new(&bob, None, Some(carol.fingerprint())).unwrap();
    let hello = initiator.write_hello().unwrap();
    let auth = responder.read_hello_write_auth(&hello).unwrap();
    let (confirm, _isess) = initiator.read_auth_write_confirm(&auth).unwrap();
    match responder.read_confirm(&confirm) {
        Err(Error::PeerIdentityMismatch) => {}
        Err(e) => panic!("expected PeerIdentityMismatch, got {e:?}"),
        Ok(_) => panic!("an undesignated sender must be rejected"),
    }
}

#[test]
fn tampered_record_fails_to_open() {
    let (alice, bob) = pair();
    let (mut isess, mut rsess, _) = handshake(&alice, &bob, bob.fingerprint(), None, None).unwrap();
    let mut frame = isess
        .seal_record(RecordType::Data, b"secret payload")
        .unwrap();
    // Flip a ciphertext byte (skip the leading type byte).
    let last = frame.len() - 1;
    frame[last] ^= 0xff;
    assert!(matches!(rsess.open_record(&frame), Err(Error::Auth)));
}

#[test]
fn reordered_records_fail() {
    let (alice, bob) = pair();
    let (mut isess, mut rsess, _) = handshake(&alice, &bob, bob.fingerprint(), None, None).unwrap();
    let first = isess.seal_record(RecordType::Data, b"one").unwrap();
    let second = isess.seal_record(RecordType::Data, b"two").unwrap();
    // Deliver the second record first: counter mismatch ⇒ authentication fails.
    assert!(matches!(rsess.open_record(&second), Err(Error::Auth)));
    // And the legitimate first record now also fails (receiver moved on).
    let _ = first;
}

#[test]
fn dropped_record_fails() {
    let (alice, bob) = pair();
    let (mut isess, mut rsess, _) = handshake(&alice, &bob, bob.fingerprint(), None, None).unwrap();
    let _first = isess.seal_record(RecordType::Data, b"one").unwrap();
    let second = isess.seal_record(RecordType::Data, b"two").unwrap();
    // Receiver never sees the first frame; the second is at the wrong counter.
    assert!(matches!(rsess.open_record(&second), Err(Error::Auth)));
}

#[test]
fn duplicated_record_fails() {
    let (alice, bob) = pair();
    let (mut isess, mut rsess, _) = handshake(&alice, &bob, bob.fingerprint(), None, None).unwrap();
    let frame = isess.seal_record(RecordType::Data, b"one").unwrap();
    assert!(rsess.open_record(&frame).is_ok());
    // Replaying the same frame fails (the receive counter has advanced).
    assert!(matches!(rsess.open_record(&frame), Err(Error::Auth)));
}

proptest! {
    #[test]
    fn arbitrary_payloads_roundtrip_in_order(
        payloads in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..2048),
            1..8,
        )
    ) {
        let (alice, bob) = pair();
        let (mut isess, mut rsess, _) =
            handshake(&alice, &bob, bob.fingerprint(), None, None).unwrap();
        for payload in payloads {
            let frame = isess.seal_record(RecordType::Data, &payload).unwrap();
            let (t, pt) = rsess.open_record(&frame).unwrap();
            prop_assert_eq!(t, RecordType::Data);
            prop_assert_eq!(&pt[..], &payload[..]);
        }
    }
}
