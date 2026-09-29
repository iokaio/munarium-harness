// SPDX-License-Identifier: Apache-2.0
//! Munarium Harness: implementation scaffolding only.
//!
//! Client-side proposal building, typed outcome retrieval, and refusal diagnostics.
//!
//! These modules declare proposed in-process interfaces with associated types.
//! There are no implementations, wire contracts, listeners, storage backends,
//! credentials, or runtime capabilities. No production path is qualified.
//! See `docs/architecture.md` and `docs/implementation-plan.md` in this repository.
//!
//! The interfaces are provisional and may change before the first implementation.
//! Concrete cross-component types must follow an accepted hub decision and contract.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod client;
pub mod proposal;
pub mod recovery;
