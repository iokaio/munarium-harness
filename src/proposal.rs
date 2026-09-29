// SPDX-License-Identifier: Apache-2.0
//! Assemble a proposal for the native Action API.
//!
//! This is client convenience. Canonicalization must follow the future hub vectors and Gate independently validates the request.
//!
//! Proposed local interface only. No implementation or wire format is provided.

/// Proposed boundary for: assemble a proposal for the native Action API.
///
/// Implementations and concrete types await the component design and hub contracts.
/// This declaration does not enforce authentication, authorization, or durability.
pub trait ProposalBuilder {
    /// Input whose concrete shape and validation rules are still to be specified.
    type Draft;
    /// Output whose concrete shape and evidence requirements are still to be specified.
    type Proposal;
    /// Failure reported without manufacturing a successful or authorized result.
    type Error;

    /// Assemble a proposal for the native Action API.
    ///
    /// # Errors
    ///
    /// Implementations must report failed validation or unavailable required dependencies.
    fn build(&self, input: &Self::Draft) -> Result<Self::Proposal, Self::Error>;
}
