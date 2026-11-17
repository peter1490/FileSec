//! Direct network transfer (the `net` feature): the UI state of a running
//! listener/sender, applying its events, and the Transfer screen.

use gpui_kit::component::progress::Progress;
use gpui_kit::component::spinner::Spinner;
use gpui_kit::{div, prelude::*, px, AnyElement, App, Context, Div, SharedString};

use filesec_core::contacts::{ContactBook, Trust};
use filesec_core::identity::Identity;
use filesec_core::util::hex;

use crate::theme::{self, ico, icon};

use super::fields;
use super::model::human_size;
use super::views::{any, checkbox, dropdown, View};
use super::{Action, FileSecApp, Session, State};

/// Content width from which Receive and Send sit side by side.
const TWO_COLUMN_MIN_W: f32 = 760.0;

/// All direct-transfer UI state: the running transfer, if any, plus the
/// receive/send form choices (the typed fields live in `Fields`). Lives in the
/// [`Session`] so it survives navigation and is torn down (stopping the worker)
/// when the session drops on lock or exit.
#[derive(Default)]
pub(super) struct TransferState {
    /// The running listener or sender, if any.
    pub active: Option<ActiveTransfer>,
    // Receive form.
    pub recv_contact: Option<String>, // hex fingerprint of the designated sender
    pub recv_internet: bool,
    // Send form.
    pub send_contact: Option<String>, // hex fingerprint of the chosen verified contact
    pub send_vault: Option<String>,   // vault id to send
    /// Explicit consent to send classical-only to a contact without
    /// post-quantum keys (only offered when that would be a downgrade).
    pub send_allow_classical: bool,
}

/// A running transfer and the UI view of its progress.
pub(super) struct ActiveTransfer {
    handle: crate::net::NetHandle,
    pub kind: ActiveKind,
    status: String,
    listen: Option<ListenView>,
    peer: Option<String>,
    pub offer: Option<OfferView>,
    progress: Option<(u64, u64)>,
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub(super) enum ActiveKind {
    Receive,
    Send,
}

/// The listening address(es) + transfer code shown to the user in receive mode.
struct ListenView {
    lan_addr: String,
    public_addr: Option<String>,
    nat: String,
    transfer_code: String,
}

/// A pending incoming offer awaiting the user's accept/reject.
pub(super) struct OfferView {
    filename: String,
    size: u64,
    sender: String,
}

impl FileSecApp {
    /// Drain transfer events from the worker and apply them. Event-driven: the
    /// worker wakes the UI (through the repaint pump) whenever it emits, so an
    /// idle listener costs nothing.
    pub(super) fn poll_transfer(&mut self, cx: &mut Context<Self>) {
        let mut events = Vec::new();
        if let State::Unlocked(s) = &self.state {
            if let Some(t) = &s.transfer.active {
                while let Some(event) = t.handle.try_recv() {
                    events.push(event);
                }
            }
        }
        if events.is_empty() {
            return;
        }
        for event in events {
            self.apply_net_event(event);
        }
        self.arm_toast_timer(cx);
    }

    /// Apply one transfer event to the session state (and toasts / registry).
    fn apply_net_event(&mut self, event: crate::net::NetEvent) {
        use crate::net::{NatStatus, NetEvent};

        // A completed receive updates the registry (needs store + identity) + toasts.
        if let NetEvent::Received {
            meta,
            file_count,
            sender_name,
            suite,
        } = &event
        {
            let classical_from_hybrid_peer = !suite.is_hybrid()
                && matches!(&self.state, State::Unlocked(s) if s.identity.is_hybrid_capable());
            if let (Some(store), Some(identity)) = (self.store_arc(), self.ident_arc()) {
                if let State::Unlocked(s) = &mut self.state {
                    s.registry.upsert(meta.clone());
                    let _ = store.save_registry(&identity, &s.registry);
                    if let Some(t) = &mut s.transfer.active {
                        t.progress = None;
                        t.offer = None;
                        t.status = "Listening for the next transfer…".into();
                    }
                }
            }
            let who = sender_name
                .clone()
                .unwrap_or_else(|| "a verified contact".into());
            let protection = if classical_from_hybrid_peer {
                " It arrived with classical protection only (the sender used a classical container)."
            } else {
                ""
            };
            self.set_toast(
                format!(
                    "Received \u{201c}{}\u{201d} from {who} ({file_count} file(s)).{protection}",
                    meta.name
                ),
                false,
            );
            return;
        }

        let mut toast: Option<(String, bool)> = None;
        if let State::Unlocked(s) = &mut self.state {
            match event {
                NetEvent::Listening {
                    lan_addr,
                    public_addr,
                    nat,
                    transfer_code,
                } => {
                    let nat = match nat {
                        NatStatus::Disabled => "Local network only.".to_string(),
                        NatStatus::Mapped => "Router port opened.".to_string(),
                        NatStatus::Unavailable(m) => format!(
                            "Couldn't open a router port ({m}). You're still reachable on your local network."
                        ),
                    };
                    if let Some(t) = &mut s.transfer.active {
                        t.status = "Listening for a sender…".into();
                        t.listen = Some(ListenView {
                            lan_addr,
                            public_addr,
                            nat,
                            transfer_code,
                        });
                    }
                }
                NetEvent::Connecting => {
                    if let Some(t) = &mut s.transfer.active {
                        t.status = "Connecting…".into();
                    }
                }
                NetEvent::Status(msg) => {
                    if let Some(t) = &mut s.transfer.active {
                        t.status = msg;
                    }
                }
                NetEvent::PeerConnected {
                    fpr_hex,
                    name,
                    verified,
                } => {
                    if let Some(t) = &mut s.transfer.active {
                        let who = name
                            .unwrap_or_else(|| format!("{}…", &fpr_hex[..fpr_hex.len().min(16)]));
                        t.peer = Some(if verified {
                            format!("{who} (verified)")
                        } else {
                            format!("{who} (unverified)")
                        });
                        t.status = "Connected".into();
                    }
                }
                NetEvent::Offer {
                    filename,
                    size,
                    sender_name,
                    verified: _,
                } => {
                    if let Some(t) = &mut s.transfer.active {
                        t.offer = Some(OfferView {
                            filename,
                            size,
                            sender: sender_name.unwrap_or_else(|| "a verified contact".into()),
                        });
                    }
                }
                NetEvent::Progress { done, total } => {
                    if let Some(t) = &mut s.transfer.active {
                        t.progress = Some((done, total));
                    }
                }
                NetEvent::Sent { vault_name } => {
                    toast = Some((format!("Sent \u{201c}{vault_name}\u{201d}."), false));
                    s.transfer.active = None;
                }
                NetEvent::Declined => {
                    toast = Some(("The receiver declined the transfer.".into(), true));
                    s.transfer.active = None;
                }
                NetEvent::Error(msg) => {
                    let is_send = s
                        .transfer
                        .active
                        .as_ref()
                        .is_some_and(|a| a.kind == ActiveKind::Send);
                    toast = Some((msg, true));
                    if is_send {
                        s.transfer.active = None;
                    } else if let Some(t) = &mut s.transfer.active {
                        t.offer = None;
                        t.progress = None;
                        t.status = "Listening for the next transfer…".into();
                    }
                }
                NetEvent::Stopped => s.transfer.active = None,
                NetEvent::Received { .. } => {} // handled above
            }
        }
        if let Some((msg, error)) = toast {
            self.set_toast(msg, error);
        }
    }

    /// Begin listening (receive mode).
    pub(super) fn start_listen(&mut self, cx: &App) {
        let (store, identity) = match (self.store_arc(), self.ident_arc()) {
            (Some(s), Some(i)) => (s, i),
            _ => return,
        };
        let port = fields::value(&self.fields.recv_port, cx).to_string();
        let built = match &self.state {
            State::Unlocked(s) if s.transfer.active.is_none() => {
                build_listen_config(&s.transfer, &s.contacts, &port)
                    .map(|c| (c, s.contacts.clone()))
            }
            _ => return,
        };
        let (config, contacts) = match built {
            Ok(x) => x,
            Err(msg) => {
                self.set_toast(msg, true);
                return;
            }
        };
        let handle =
            crate::net::start_listener(config, identity, store, contacts, self.repaint.clone());
        if let State::Unlocked(s) = &mut self.state {
            s.transfer.active = Some(ActiveTransfer {
                handle,
                kind: ActiveKind::Receive,
                status: "Starting…".into(),
                listen: None,
                peer: None,
                offer: None,
                progress: None,
            });
        }
    }

    /// Begin sending (send mode).
    pub(super) fn start_send(&mut self, cx: &App) {
        let (store, identity) = match (self.store_arc(), self.ident_arc()) {
            (Some(s), Some(i)) => (s, i),
            _ => return,
        };
        let form = SendFields {
            host: fields::value(&self.fields.send_host, cx).to_string(),
            port: fields::value(&self.fields.send_port, cx).to_string(),
            pairing: fields::value(&self.fields.send_pairing, cx).to_string(),
        };
        let built = match &self.state {
            State::Unlocked(s) if s.transfer.active.is_none() => {
                build_send_config(&s.transfer, &form, &s.contacts, &s.identity)
            }
            _ => return,
        };
        let config = match built {
            Ok(c) => c,
            Err(msg) => {
                self.set_toast(msg, true);
                return;
            }
        };
        let handle = crate::net::start_sender(config, identity, store, self.repaint.clone());
        if let State::Unlocked(s) = &mut self.state {
            s.transfer.active = Some(ActiveTransfer {
                handle,
                kind: ActiveKind::Send,
                status: "Connecting…".into(),
                listen: None,
                peer: None,
                offer: None,
                progress: None,
            });
        }
    }

    /// Stop the active listener/sender and clear it (the worker unmaps any NAT port).
    pub(super) fn stop_transfer(&mut self) {
        if let State::Unlocked(s) = &mut self.state {
            if let Some(t) = &mut s.transfer.active {
                t.handle.stop();
            }
            s.transfer.active = None;
        }
    }

    /// Forward a command (accept/reject/cancel) to the active transfer.
    pub(super) fn transfer_command(&mut self, command: crate::net::NetCommand, clear_offer: bool) {
        if let State::Unlocked(s) = &mut self.state {
            if let Some(t) = &mut s.transfer.active {
                t.handle.send(command);
                if clear_offer {
                    t.offer = None;
                    t.status = "Receiving…".into();
                }
            }
        }
    }
}

/// The send form's typed fields.
struct SendFields {
    host: String,
    port: String,
    pairing: String,
}

/// The user's verified contacts as `(fingerprint_hex, display_name)`.
fn verified_contacts(s: &Session) -> Vec<(String, String)> {
    s.contacts
        .contacts
        .iter()
        .filter(|c| c.trust == Trust::Verified)
        .map(|c| {
            let name = if c.identity.name.is_empty() {
                "(unnamed)".to_string()
            } else {
                c.identity.name.clone()
            };
            (hex(&c.fingerprint()), name)
        })
        .collect()
}

/// The display name for the selected `(id, name)` option, or a placeholder.
fn combo_label(
    selected: &Option<String>,
    options: &[(String, String)],
    placeholder: &str,
) -> String {
    selected
        .as_ref()
        .and_then(|sel| options.iter().find(|(id, _)| id == sel))
        .map(|(_, name)| name.clone())
        .unwrap_or_else(|| placeholder.to_string())
}

/// Validate the receive form into a [`crate::net::ListenConfig`], or a user-facing error.
fn build_listen_config(
    forms: &TransferState,
    contacts: &ContactBook,
    recv_port: &str,
) -> Result<crate::net::ListenConfig, String> {
    let fpr_hex = forms
        .recv_contact
        .clone()
        .ok_or_else(|| "Pick the verified contact you expect to receive from.".to_string())?;
    let contact = contacts
        .contacts
        .iter()
        .find(|c| c.trust == Trust::Verified && hex(&c.fingerprint()) == fpr_hex)
        .ok_or_else(|| "Pick the verified contact you expect to receive from.".to_string())?;
    let port = if recv_port.trim().is_empty() {
        0
    } else {
        recv_port
            .trim()
            .parse::<u16>()
            .map_err(|_| "Enter a valid port number, or leave it blank for auto.".to_string())?
    };
    Ok(crate::net::ListenConfig {
        port,
        internet: forms.recv_internet,
        expected_sender_fpr: Some(contact.fingerprint()),
    })
}

/// Validate the send form into a [`crate::net::SendConfig`], or a user-facing error.
fn build_send_config(
    forms: &TransferState,
    typed: &SendFields,
    contacts: &ContactBook,
    identity: &Identity,
) -> Result<crate::net::SendConfig, String> {
    let fpr_hex = forms
        .send_contact
        .clone()
        .ok_or_else(|| "Pick a verified contact to send to.".to_string())?;
    let contact = contacts
        .contacts
        .iter()
        .find(|c| c.trust == Trust::Verified && hex(&c.fingerprint()) == fpr_hex)
        .ok_or_else(|| "Pick a verified contact to send to.".to_string())?;
    let host = typed.host.trim().to_string();
    if host.is_empty() {
        return Err("Enter the receiver's address.".into());
    }
    let port = typed
        .port
        .trim()
        .parse::<u16>()
        .ok()
        .filter(|p| *p != 0)
        .ok_or_else(|| "Enter a valid port number.".to_string())?;
    let vault_id = forms
        .send_vault
        .clone()
        .ok_or_else(|| "Pick a vault to send.".to_string())?;
    let transfer_code = {
        let p = typed.pairing.trim();
        if p.is_empty() {
            return Err("Enter the transfer code the receiver is showing.".into());
        }
        Some(p.to_string())
    };
    let downgrade = crate::net::transfer_downgrades_protection(identity, &contact.identity);
    if downgrade && !forms.send_allow_classical {
        return Err(crate::net::CLASSICAL_SEND_NEEDS_CONSENT.into());
    }
    Ok(crate::net::SendConfig {
        host,
        port,
        recipient: contact.identity.clone(),
        recipient_fpr: contact.fingerprint(),
        transfer_code,
        vault_id,
        allow_classical: downgrade && forms.send_allow_classical,
    })
}

/// Whether a transfer is doing visible work, as opposed to a listener idling
/// for a sender (which shows a static glyph rather than a spinner).
fn transfer_is_busy(active: &ActiveTransfer) -> bool {
    active.kind == ActiveKind::Send
        || active.peer.is_some()
        || active.offer.is_some()
        || active.progress.is_some()
}

pub(super) fn transfer(s: &Session, v: &View) -> impl IntoElement {
    let c = v.c;
    let mut body = vec![any(theme::page_description(
        "Send a vault straight to a verified contact over the network — no server in \
         between. Keep both apps open during the transfer.",
        c,
    ))];
    match &s.transfer.active {
        Some(active) => body.push(any(active_transfer_card(active, v))),
        // Wide enough: the two directions side by side, so neither is a long
        // narrow column next to empty space.
        None if v.width >= px(TWO_COLUMN_MIN_W) => body.push(any(theme::row()
            .w_full()
            .items_start()
            .gap(px(16.0))
            .child(receive_card(s, v).flex_1().min_w_0())
            .child(send_card(s, v).flex_1().min_w_0()))),
        None => {
            body.push(any(receive_card(s, v)));
            body.push(any(send_card(s, v)));
        }
    }
    super::views::page("transfer-scroll", "Transfer", None, body, v)
}

fn card_title(glyph: icon::Glyph, title: &'static str, subtitle: &'static str, v: &View) -> Div {
    theme::row()
        .w_full()
        .gap(px(12.0))
        .child(theme::icon_tile(
            glyph,
            34.0,
            v.c.accent,
            theme::accent_soft(v.c),
        ))
        .child(
            div()
                .flex_1()
                .min_w_0()
                .flex()
                .flex_col()
                .child(theme::strong(title, theme::TEXT_H2, v.c.text))
                .child(theme::muted(subtitle, v.c)),
        )
}

fn receive_card(s: &Session, v: &View) -> Div {
    let c = v.c;
    let mut card = theme::card(c).child(card_title(
        icon::DOWNLOAD,
        "Receive",
        "Wait for a contact you choose to send you a vault.",
        v,
    ));
    let verified = verified_contacts(s);
    if verified.is_empty() {
        return card.child(theme::muted(
            "Add and verify the contact you expect to receive from first.",
            c,
        ));
    }
    let label = combo_label(&s.transfer.recv_contact, &verified, "Choose a contact…");
    let items = verified
        .iter()
        .map(|(fp, name)| {
            (
                SharedString::from(name.clone()),
                Action::SetRecvContact(fp.clone()),
                s.transfer.recv_contact.as_deref() == Some(fp.as_str()),
            )
        })
        .collect();
    card = card
        .child(theme::caption("Receive from", c))
        .child(
            div()
                .w_full()
                .child(dropdown("recv-contact", label, items, v)),
        )
        .child(theme::muted(
            "Only this contact will be able to send to you.",
            c,
        ))
        .child(checkbox(
            "recv-internet",
            "Reachable over the internet (open a port on my router)",
            s.transfer.recv_internet,
            v.on_check(Action::SetRecvInternet),
        ))
        .child(
            theme::row()
                .child(theme::text("Port", c.text))
                .child(
                    div()
                        .w(px(110.0))
                        .child(super::views::text_input(&v.fields.recv_port)),
                )
                .child(theme::muted("(optional)", c)),
        );
    if s.transfer.recv_internet {
        card = card.child(theme::muted(
            "If your router can't open the port (NAT-PMP), you'll still be reachable on your \
             local network.",
            c,
        ));
    }
    card.child(
        theme::row().justify_end().child(
            theme::primary_button("start-listen", "Start listening")
                .icon(ico(icon::DOWNLOAD))
                .on_click(v.on(Action::StartListen)),
        ),
    )
}

fn send_card(s: &Session, v: &View) -> Div {
    let c = v.c;
    let card = theme::card(c).child(card_title(
        icon::SEND,
        "Send",
        "Send one of your vaults to a verified contact.",
        v,
    ));
    let verified = verified_contacts(s);
    if verified.is_empty() {
        return card.child(theme::muted(
            "Add and verify a contact first — you can only send to verified contacts.",
            c,
        ));
    }
    let vaults: Vec<(String, String)> = s
        .registry
        .vaults
        .iter()
        .map(|vm| (vm.id.clone(), vm.name.clone()))
        .collect();
    if vaults.is_empty() {
        return card.child(theme::muted("Create a vault to send first.", c));
    }
    let contact_label = combo_label(&s.transfer.send_contact, &verified, "Choose a contact…");
    let contact_items = verified
        .iter()
        .map(|(fp, name)| {
            (
                SharedString::from(name.clone()),
                Action::SetSendContact(fp.clone()),
                s.transfer.send_contact.as_deref() == Some(fp.as_str()),
            )
        })
        .collect();
    let vault_label = combo_label(&s.transfer.send_vault, &vaults, "Choose a vault…");
    let vault_items = vaults
        .iter()
        .map(|(vid, name)| {
            (
                SharedString::from(name.clone()),
                Action::SetSendVault(vid.clone()),
                s.transfer.send_vault.as_deref() == Some(vid.as_str()),
            )
        })
        .collect();
    // Hybrid protection travels with the data only if the recipient has
    // post-quantum keys too. Otherwise say so, and require a decision.
    let downgrade = s.transfer.send_contact.as_deref().is_some_and(|fp| {
        s.contacts
            .contacts
            .iter()
            .find(|ct| hex(&ct.fingerprint()) == fp)
            .is_some_and(|ct| crate::net::transfer_downgrades_protection(&s.identity, &ct.identity))
    });
    let mut card = card
        .child(theme::caption("Send to", c))
        .child(
            div()
                .w_full()
                .child(dropdown("send-contact", contact_label, contact_items, v)),
        )
        .child(theme::caption("Vault", c))
        .child(
            div()
                .w_full()
                .child(dropdown("send-vault", vault_label, vault_items, v)),
        )
        .child(theme::caption("Address", c))
        .child(
            theme::row()
                .w_full()
                .child(
                    div()
                        .flex_1()
                        .child(super::views::text_input(&v.fields.send_host)),
                )
                .child(theme::text(":", c.text))
                .child(
                    div()
                        .w(px(80.0))
                        .child(super::views::text_input(&v.fields.send_port)),
                ),
        )
        .child(theme::caption("Transfer code (from the receiver)", c))
        .child(
            div()
                .w(px(260.0))
                .child(super::views::text_input(&v.fields.send_pairing)),
        );
    if downgrade {
        card = card
            .child(theme::small(
                "This contact has no post-quantum keys. The vault would be sent with \
                 classical protection only (X25519/Ed25519), not the hybrid protection \
                 your vaults have at rest. Ask them to upgrade their identity, or confirm:",
                c.warn,
            ))
            .child(checkbox(
                "send-allow-classical",
                "Send with classical protection only",
                s.transfer.send_allow_classical,
                v.on_check(Action::SetSendAllowClassical),
            ));
    }
    card.child(
        theme::row().justify_end().child(
            theme::primary_button("start-send", "Send")
                .icon(ico(icon::SEND))
                .on_click(v.on(Action::StartSend)),
        ),
    )
}

fn addr_row(id: &'static str, label: &'static str, addr: &str, v: &View) -> Div {
    let c = v.c;
    theme::row()
        .child(theme::muted(label, c))
        .child(theme::mono(
            addr.to_string(),
            theme::TEXT_MONO,
            c.text,
            v.cx,
        ))
        .child(
            theme::icon_button(id, icon::COPY, "Copy address", c)
                .on_click(v.on(Action::CopyText(addr.to_string()))),
        )
}

fn active_transfer_card(active: &ActiveTransfer, v: &View) -> Div {
    let c = v.c;
    // The header IS the live phase, so it always matches what's actually
    // happening — e.g. "Listening for a sender…" while waiting. A spinner shows
    // only while something is actually happening; an idle listener gets a
    // static glyph.
    let mut card = theme::card(c).child(
        theme::row()
            .child(if transfer_is_busy(active) {
                any(Spinner::new().color(c.accent))
            } else {
                any(theme::icon_text(icon::DOWNLOAD, 18.0, c.accent))
            })
            .child(theme::strong(active.status.clone(), px(15.0), c.text)),
    );
    if let Some(peer) = &active.peer {
        card = card.child(theme::text(format!("Peer: {peer}"), c.text_muted));
    }
    if let Some(lv) = &active.listen {
        card = card.child(theme::separator(c)).child(addr_row(
            "copy-lan",
            "On this network",
            &lv.lan_addr,
            v,
        ));
        if let Some(pa) = &lv.public_addr {
            card = card.child(addr_row("copy-public", "Over the internet", pa, v));
        }
        card = card
            .child(theme::muted(lv.nat.clone(), c))
            .child(
                theme::wrap_row()
                    .child(theme::text("Transfer code:", c.text))
                    .child(
                        theme::mono(lv.transfer_code.clone(), px(16.0), c.accent, v.cx)
                            .font_weight(gpui_kit::FontWeight::BOLD),
                    )
                    .child(
                        theme::icon_button("copy-code", icon::COPY, "Copy transfer code", c)
                            .on_click(v.on(Action::CopyText(lv.transfer_code.clone()))),
                    ),
            )
            .child(theme::muted(
                "Give the address and this one-time code to the sender. The transfer can't \
                 start until they enter it — it also keeps your identity private from anyone \
                 who doesn't have it.",
                c,
            ));
    }
    if let Some((done, total)) = active.progress {
        let frac = if total > 0 {
            (done as f32 / total as f32).clamp(0.0, 1.0)
        } else {
            0.0
        };
        card = card
            .child(
                Progress::new("transfer-progress")
                    .value(frac * 100.0)
                    .accessibility_label(SharedString::from(format!("{:.0}%", frac * 100.0))),
            )
            .child(theme::muted(
                format!(
                    "{:.0}% · {} / {}",
                    frac * 100.0,
                    human_size(done),
                    human_size(total)
                ),
                c,
            ));
    }
    let (label, act) = match active.kind {
        ActiveKind::Receive => ("Stop listening", Action::StopTransfer),
        ActiveKind::Send => ("Cancel", Action::CancelTransfer),
    };
    card.child(
        theme::row().child(theme::danger_button("stop-transfer", label, v.cx).on_click(v.on(act))),
    )
}

/// The "Incoming transfer" dialog for a pending offer.
pub(super) fn offer_dialog(s: &Session, v: &View) -> Option<AnyElement> {
    let c = v.c;
    let offer = s.transfer.active.as_ref().and_then(|a| a.offer.as_ref())?;
    let body = div()
        .flex()
        .flex_col()
        .gap(px(14.0))
        .child(theme::text(
            format!("{} wants to send you:", offer.sender),
            c.text_muted,
        ))
        .child(
            theme::row()
                .w_full()
                .gap(px(12.0))
                .p(px(12.0))
                .rounded(theme::RADIUS)
                .border_1()
                .border_color(c.border_subtle)
                .child(theme::icon_tile(
                    icon::VAULT,
                    36.0,
                    c.accent,
                    theme::accent_soft(c),
                ))
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .flex()
                        .flex_col()
                        .child(theme::one_line(theme::strong(
                            offer.filename.clone(),
                            theme::TEXT_BODY,
                            c.text,
                        )))
                        .child(theme::muted(human_size(offer.size), c)),
                ),
        )
        .child(theme::callout(
            icon::INFO,
            "Only accept files you're expecting from this contact.",
            c.text_muted,
            c,
        ));
    let footer = super::views::dialogs::footer()
        .child(
            theme::secondary_button("reject-offer", "Decline")
                .on_click(v.on(Action::RejectIncoming)),
        )
        .child(
            theme::primary_button("accept-offer", "Accept")
                .icon(ico(icon::DOWNLOAD))
                .on_click(v.on(Action::AcceptIncoming)),
        );
    Some(super::views::dialogs::modal(
        "offer",
        "Incoming transfer",
        None,
        body,
        footer,
        v,
    ))
}
