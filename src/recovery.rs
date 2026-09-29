// SPDX-License-Identifier: Apache-2.0
//! Look up the recorded state of an existing operation.
//!
//! Lookup must not resubmit. Unresolved outcomes are investigation items, not retryable transport failures.
//!
//! Proposed local interface only. No implementation or wire format is provided.

/// Proposed boundary for: look up the recorded state of an existing operation.
///
/// Implementations and concrete types await the component design and hub contracts.
/// This declaration does not enforce authentication, authorization, or durability.
pub trait OutcomeReader {
    /// Input whose concrete shape and validation rules are still to be specified.
    type OperationReference;
    /// Output whose concrete shape and evidence requirements are still to be specified.
    type Outcome;
    /// Failure reported without manufacturing a successful or authorized result.
    type Error;

    /// Look up the recorded state of an existing operation.
    ///
    /// # Errors
    ///
    /// Implementations must report failed validation or unavailable required dependencies.
    fn lookup(&self, input: &Self::OperationReference) -> Result<Self::Outcome, Self::Error>;
}
