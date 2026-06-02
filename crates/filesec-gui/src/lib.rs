//! FileSec desktop app library: the egui [`app`] and the on-disk [`store`].
//!
//! Split into a library so the persistence layer can be integration-tested
//! without spawning a window. The `filesec` binary is a thin entry point over
//! [`app::App`].

pub mod app;
pub mod passkey;
pub mod store;
