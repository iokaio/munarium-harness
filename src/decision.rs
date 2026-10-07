// SPDX-License-Identifier: Apache-2.0
//! Experimental ADR-0004 proposal bytes and closed outcomes. No execution authority.
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use std::fmt;

/// Sanitized protocol failure, without request contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Ambiguous, oversized, incompatible or malformed input.
    InvalidInput,
    /// The recipient returned a different request or operation binding.
    Binding,
    /// Transport ambiguity requires lookup, never automatic resubmission.
    Unresolved,
    /// A bound, recorded pre-evaluation refusal, distinct from transport ambiguity.
    Refused,
}

struct Strict(Value);
impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Strict;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("decision-json-v1")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Strict, E> {
                Ok(Strict(Value::Bool(v)))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Strict, E> {
                Ok(Strict(Value::String(v.into())))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Strict, E> {
                if !(-9_007_199_254_740_991..=9_007_199_254_740_991).contains(&v) {
                    return Err(E::custom("integer range"));
                }
                Ok(Strict(Value::Number(Number::from(v))))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Strict, E> {
                if v > 9_007_199_254_740_991 {
                    return Err(E::custom("integer range"));
                }
                self.visit_i64(v as i64)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Strict, A::Error> {
                let mut values = Vec::new();
                while let Some(Strict(v)) = a.next_element()? {
                    values.push(v);
                }
                Ok(Strict(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Strict, A::Error> {
                let mut values = Map::new();
                while let Some(k) = a.next_key::<String>()? {
                    if !k.is_ascii() || values.contains_key(&k) {
                        return Err(de::Error::custom("member"));
                    }
                    let Strict(v) = a.next_value()?;
                    values.insert(k, v);
                }
                Ok(Strict(Value::Object(values)))
            }
        }
        d.deserialize_any(V)
    }
}

/// Canonicalize the restricted profile, rejecting ambiguity before building a map.
pub fn canonical(raw: &[u8]) -> Result<Vec<u8>, Error> {
    if raw.len() > 65_536 {
        return Err(Error::InvalidInput);
    }
    let Strict(v) = serde_json::from_slice(raw).map_err(|_| Error::InvalidInput)?;
    fn depth(v: &Value, n: usize) -> bool {
        match v {
            Value::Object(m) => n < 16 && m.values().all(|v| depth(v, n + 1)),
            Value::Array(a) => n < 16 && a.iter().all(|v| depth(v, n + 1)),
            _ => true,
        }
    }
    if !v.is_object() || !depth(&v, 0) {
        return Err(Error::InvalidInput);
    }
    serde_json::to_vec(&v).map_err(|_| Error::InvalidInput)
}

/// Domain-separated request digest over independently canonicalized bytes.
pub fn request_digest(raw: &[u8]) -> Result<String, Error> {
    let mut hash = Sha256::new();
    hash.update(b"munarium:decision-request:v1\0");
    hash.update(canonical(raw)?);
    Ok(format!("sha256:{:x}", hash.finalize()))
}

fn id(v: &Value) -> bool {
    v.as_str().is_some_and(|s| {
        !s.is_empty()
            && s.len() <= 128
            && s.as_bytes()[0].is_ascii_alphanumeric()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b":._/-".contains(&b))
    })
}
fn digest(v: &Value) -> bool {
    v.as_str().is_some_and(|s| {
        s.len() == 71
            && s.starts_with("sha256:")
            && s.as_bytes()[7..]
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    })
}

/// Validated proposal with stable tenant/operation identity and canonical bytes.
#[derive(Clone, Debug)]
pub struct Proposal {
    value: Value,
    bytes: Vec<u8>,
    digest: String,
}
impl Proposal {
    /// Build an ADR-0004 request; this performs no server-side authorization.
    pub fn parse(raw: &[u8]) -> Result<Self, Error> {
        let bytes = canonical(raw)?;
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| Error::InvalidInput)?;
        const FIELDS: &[&str] = &[
            "schema_version",
            "profile",
            "tenant",
            "operation_id",
            "principal_digest",
            "target_id",
            "environment",
            "capability_id",
            "manifest_digest",
            "policy_digest",
            "activation_epoch",
            "mode",
            "parameters",
            "attachments",
        ];
        let fields = value.as_object().ok_or(Error::InvalidInput)?;
        if fields.len() != FIELDS.len()
            || FIELDS.iter().any(|f| !fields.contains_key(*f))
            || value["schema_version"] != 1
            || value["profile"] != "decision-json-v1"
            || [
                "tenant",
                "operation_id",
                "target_id",
                "environment",
                "capability_id",
            ]
            .iter()
            .any(|f| !id(&value[*f]))
            || ["principal_digest", "manifest_digest", "policy_digest"]
                .iter()
                .any(|f| !digest(&value[*f]))
            || value["activation_epoch"].as_u64().is_none()
            || !matches!(
                value["mode"].as_str(),
                Some("observe" | "advise" | "guard" | "enforce" | "assure")
            )
            || !value["parameters"].is_object()
        {
            return Err(Error::InvalidInput);
        }
        let attachments = value["attachments"].as_array().ok_or(Error::InvalidInput)?;
        let mut total = 0u64;
        if attachments.len() > 8 {
            return Err(Error::InvalidInput);
        }
        for a in attachments {
            if a.as_object().is_none_or(|o| o.len() != 3)
                || !digest(&a["digest"])
                || a["media_type"]
                    .as_str()
                    .is_none_or(|s| s.is_empty() || s.chars().count() > 1024)
            {
                return Err(Error::InvalidInput);
            }
            total = total
                .checked_add(a["bytes"].as_u64().ok_or(Error::InvalidInput)?)
                .ok_or(Error::InvalidInput)?;
            if total > 1_048_576 {
                return Err(Error::InvalidInput);
            }
        }
        let digest = request_digest(&bytes)?;
        Ok(Self {
            value,
            bytes,
            digest,
        })
    }
    /// Exact canonical request bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Request digest computed by this client; Gate recomputes it independently.
    pub fn digest(&self) -> &str {
        &self.digest
    }
    /// Tenant for lookup and response binding.
    pub fn tenant(&self) -> &str {
        self.value["tenant"].as_str().expect("validated tenant")
    }
    /// Stable operation identity; retain before the first submission.
    pub fn operation_id(&self) -> &str {
        self.value["operation_id"]
            .as_str()
            .expect("validated operation")
    }
}

/// Closed platform outcomes, including the non-executable Stage 1 allow.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    /// Refused.
    Denied,
    /// Needs separately bound approval; grants no authority.
    ApprovalRequired,
    /// Policy evaluation only; never execution admission.
    DecisionOnlyAllow,
    /// Later-stage recorded admission.
    AcceptedForExecution,
    /// Later-stage confirmed completion.
    Completed,
    /// Later-stage confirmed failure before dispatch.
    FailedBeforeDispatch,
    /// Investigate by lookup; never blindly retry.
    Unresolved,
}

/// Application-supplied authenticated transport. It must never retry submissions.
pub trait Transport {
    /// Submit once; ambiguity returns `Unresolved`.
    fn submit(&mut self, proposal: &Proposal) -> Result<Value, Error>;
    /// Read the original operation without sending another proposal.
    fn lookup(&mut self, tenant: &str, operation_id: &str) -> Result<Value, Error>;
}

/// Client whose only recovery action is read-only lookup.
pub struct Client<T: Transport>(pub T);
impl<T: Transport> Client<T> {
    /// Submit exactly once and check the recipient's complete operation binding.
    pub fn submit(&mut self, p: &Proposal) -> Result<Outcome, Error> {
        Self::bound(p, &self.0.submit(p)?)
    }
    /// Recover the same operation by lookup, with no submission fallback.
    pub fn lookup(&mut self, p: &Proposal) -> Result<Outcome, Error> {
        Self::bound(p, &self.0.lookup(p.tenant(), p.operation_id())?)
    }
    fn bound(p: &Proposal, v: &Value) -> Result<Outcome, Error> {
        if v["tenant"] != p.tenant()
            || v["operation_id"] != p.operation_id()
            || v["request_digest"] != p.digest()
        {
            return Err(Error::Binding);
        }
        if v.get("outcome").is_none()
            && v["schema_version"] == 1
            && v["reasons"]
                .as_array()
                .is_some_and(|r| !r.is_empty() && r.len() <= 32 && r.iter().all(id))
        {
            return Err(Error::Refused);
        }
        serde_json::from_value(v["outcome"].clone()).map_err(|_| Error::InvalidInput)
    }
}
