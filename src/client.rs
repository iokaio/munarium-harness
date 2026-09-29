// SPDX-License-Identifier: Apache-2.0
//! Submit a proposal without target execution authority.
//!
//! No default retry behavior is provided. Wire types and transport are pending the hub contract.
//!
//! Proposed local interface only. No implementation or wire format is provided.

/// Proposed boundary for: submit a proposal without target execution authority.
///
/// Implementations and concrete types await the component design and hub contracts.
/// This declaration does not enforce authentication, authorization, or durability.
pub trait ActionClient {
    /// Input whose concrete shape and validation rules are still to be specified.
    type Proposal;
    /// Output whose concrete shape and evidence requirements are still to be specified.
    type Submission;
    /// Failure reported without manufacturing a successful or authorized result.
    type Error;

    /// Submit a proposal without target execution authority.
    ///
    /// # Errors
    ///
    /// Implementations must report failed validation or unavailable required dependencies.
    fn submit(&mut self, input: &Self::Proposal) -> Result<Self::Submission, Self::Error>;
}
