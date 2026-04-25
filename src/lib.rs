// nmdns library facade.
//
// The binary in `src/main.rs` is a thin wrapper around `engine::run`. The
// library exposes every module so integration tests can drive the cache,
// services, repeater, responder, and config without binding privileged
// sockets or real network interfaces.
//
// SPDX-License-Identifier: MIT OR Apache-2.0

pub mod browser;
pub mod cache;
pub mod config;
pub mod daemon;
pub mod engine;
pub mod iface;
pub mod record_key;
pub mod repeater;
pub mod responder;
pub mod services;
pub mod state;
pub mod timing;
