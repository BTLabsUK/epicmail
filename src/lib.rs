//! epicmail, an Epicbox-compatible relay, as a library. The `epicmail` binary (`main.rs`) wires
//! these modules together; the integration tests and the load generator use them directly.
//!
//! `docs/architecture.md` describes how a message moves through the modules.

pub mod address;
pub mod clock;
pub mod config;
pub mod forward;
pub mod http;
pub mod ids;
pub mod limits;
pub mod logging;
pub mod metrics;
pub mod migrate;
pub mod relay;
pub mod sig;
pub mod store;
