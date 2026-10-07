# SPDX-License-Identifier: Apache-2.0
"""Independent Python implementation of the proposed ADR-0004 client boundary."""
from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import re
from typing import Protocol


class ProtocolError(ValueError):
    """Sanitized malformed input or response binding failure."""


class Unresolved(Exception):
    """Submission may have arrived; recover only by the original operation lookup."""


class Refused(Exception):
    """A bound, recorded pre-evaluation refusal, separate from transport ambiguity."""
    def __init__(self, reasons):
        super().__init__("recorded decision refusal")
        self.reasons = tuple(reasons)


def canonical(raw: bytes) -> bytes:
    """Reject ambiguity and return exact decision-json-v1 canonical bytes."""
    def integer(token):
        n = int(token)
        if token == "-0" or not -9007199254740991 <= n <= 9007199254740991:
            raise ProtocolError("integer")
        return n

    def unsupported(_):
        raise ProtocolError("number")

    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            if not key.isascii() or key in result:
                raise ProtocolError("member")
            result[key] = value
        return result

    def walk(value, depth=0):
        if isinstance(value, (dict, list)):
            if depth >= 16:
                raise ProtocolError("depth")
            for child in value.values() if isinstance(value, dict) else value:
                walk(child, depth + 1)
        elif isinstance(value, str):
            value.encode("utf-8", "strict")

    try:
        if len(raw) > 65536 or raw.startswith(b"\xef\xbb\xbf"):
            raise ProtocolError("size or encoding")
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=object_pairs,
                           parse_int=integer, parse_float=unsupported, parse_constant=unsupported)
        if not isinstance(value, dict):
            raise ProtocolError("object")
        walk(value)
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    except (ValueError, UnicodeError, RecursionError) as error:
        raise ProtocolError("invalid decision JSON") from None


def request_digest(raw):
    return "sha256:" + hashlib.sha256(b"munarium:decision-request:v1\0" + canonical(raw)).hexdigest()


def identifier(value):
    return isinstance(value, str) and len(value) <= 128 and re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9:._/-]*", value) is not None


def digest(value):
    return isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None


@dataclass(frozen=True)
class Proposal:
    """Immutable canonical bytes and stable identity, retained before first submit."""
    raw: bytes
    tenant: str
    operation_id: str
    digest: str

    @classmethod
    def parse(cls, raw):
        encoded = canonical(raw)
        value = json.loads(encoded)
        fields = {"schema_version", "profile", "tenant", "operation_id", "principal_digest",
                  "target_id", "environment", "capability_id", "manifest_digest", "policy_digest",
                  "activation_epoch", "mode", "parameters", "attachments"}
        if (set(value) != fields or type(value["schema_version"]) is not int or value["schema_version"] != 1
                or value["profile"] != "decision-json-v1"
                or any(not identifier(value[f]) for f in ("tenant", "operation_id", "target_id", "environment", "capability_id"))
                or any(not digest(value[f]) for f in ("principal_digest", "manifest_digest", "policy_digest"))
                or type(value["activation_epoch"]) is not int or value["activation_epoch"] < 0
                or value["mode"] not in ("observe", "advise", "guard", "enforce", "assure")
                or not isinstance(value["parameters"], dict)
                or not isinstance(value["attachments"], list) or len(value["attachments"]) > 8):
            raise ProtocolError("request shape")
        total = 0
        for a in value["attachments"]:
            if (not isinstance(a, dict) or set(a) != {"digest", "media_type", "bytes"}
                    or not digest(a["digest"]) or not isinstance(a["media_type"], str)
                    or not 1 <= len(a["media_type"]) <= 1024
                    or type(a["bytes"]) is not int or a["bytes"] < 0):
                raise ProtocolError("attachment")
            total += a["bytes"]
        if total > 1048576:
            raise ProtocolError("attachment limit")
        return cls(encoded, value["tenant"], value["operation_id"], request_digest(encoded))


class Outcome(str, Enum):
    DENIED = "denied"
    APPROVAL_REQUIRED = "approval-required"
    DECISION_ONLY_ALLOW = "decision-only-allow"
    ACCEPTED_FOR_EXECUTION = "accepted-for-execution"
    COMPLETED = "completed"
    FAILED_BEFORE_DISPATCH = "failed-before-dispatch"
    UNRESOLVED = "unresolved"


class Transport(Protocol):
    def submit(self, proposal: Proposal) -> bytes: ...
    def lookup(self, tenant: str, operation_id: str) -> bytes: ...


class Client:
    def __init__(self, transport: Transport):
        self.transport = transport

    def _bound(self, proposal, raw):
        value = json.loads(canonical(raw))
        if (value.get("tenant") != proposal.tenant or value.get("operation_id") != proposal.operation_id
                or value.get("request_digest") != proposal.digest):
            raise ProtocolError("response binding")
        try:
            if "outcome" not in value:
                reasons = value.get("reasons")
                if (value.get("schema_version") == 1 and isinstance(reasons, list)
                        and 1 <= len(reasons) <= 32 and all(identifier(r) for r in reasons)):
                    raise Refused(reasons)
            return Outcome(value["outcome"])
        except (ValueError, KeyError):
            raise ProtocolError("outcome") from None

    def submit(self, proposal: Proposal) -> Outcome:
        # A transport exception never triggers a retry or a replacement identity.
        return self._bound(proposal, self.transport.submit(proposal))

    def lookup(self, proposal: Proposal) -> Outcome:
        return self._bound(proposal, self.transport.lookup(proposal.tenant, proposal.operation_id))
