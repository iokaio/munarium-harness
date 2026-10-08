#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Retain an experimental five-service activation attempt, including failed attempts."""
import argparse
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

from run_stage1 import ROOT, sha, sources, stamp


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--execution", action="store_true", help="Also run the prepared synthetic release composition")
    parser.add_argument("--database-image", required=True, help="Observed image digest; never a database URL")
    args = parser.parse_args()
    if not args.owner.strip() or not args.database_image.startswith("sha256:"):
        raise ValueError("owner and observed image digest required")
    for name in ("MUNARIUM_PLATFORM_TEST_DATABASE_URL", "STAGE2_GATE_DATABASE_URL"):
        if not os.environ.get(name):
            raise ValueError("explicit isolated database inputs required")
    workspace = args.workspace.resolve(strict=True)
    names = ("munarium", "munarium-council", "munarium-registry", "munarium-gate", "munarium-warden")
    suffix = ".exe" if os.name == "nt" else ""
    binaries = {name: workspace / name / ("server/target/debug" if name == "munarium" else "target/debug") /
        (("munarium-server" if name == "munarium" else name)+suffix) for name in names}
    record = dict(started=stamp(), profile="stage2-activation-services-v1", status="running", owner=args.owner,
        qualification=False, independent_review="pending", sources=sources(workspace, names+("munarium-harness",)),
        binaries={name: sha(path.read_bytes()) for name, path in binaries.items()},
        environment=dict(os=platform.platform(), python=platform.python_version(), database_image=args.database_image,
            availability="all five binaries and explicit database inputs present; connectivity checked by scenario",
            cost_authority="existing local/CI host only", expiry="end of test; caller removes isolated databases",
            resource_ceiling="32 service requests; test timeout 240 seconds; caller owns database resource limits"),
        participant_outbox_delivery=True,
        exclusions=["action lifecycle outbox delivery", "snapshot restore", "execution", "target effects", "network and secret isolation"])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.execution:
        if not os.environ.get("STAGE2_DATABASE_CONTAINER"):
            raise ValueError("explicit owned database container required for snapshot/restore testing")
        record.update(profile="stage2-prepared-release-v1", execution="synthetic-only",
            openbao_image="ghcr.io/openbao/openbao:2.4.4@sha256:01bdba095690b1fe7cc1ec956ca422cfe01fd9a994ea28d9a6a2f84886dc9569",
            exclusions=["dynamic Linux policy evaluation", "production qualification", "OS network and secret isolation", "automatic restore reopening"])
        record["environment"]["resource_ceiling"] = "32 service requests; 480 seconds; OpenBao 256 MiB/1 CPU; caller owns database resource limits"
    log = args.output.with_suffix(".log")
    if log.exists():
        raise ValueError("refusing to replace prior evidence")
    with args.output.open("x", encoding="utf-8") as out:
        out.write(json.dumps(record, indent=2)+"\n")
    env = dict(os.environ, STAGE2_WORKSPACE=str(workspace), MUNARIUM_PLATFORM_TEST_BINARY=str(binaries["munarium"]))
    env["STAGE2_EXECUTION"] = "1" if args.execution else "0"
    command = [sys.executable, "-m", "pytest", "tests/network/test_activation.py", "-q", "--tb=short", "--assert=plain", "-p", "no:cacheprovider"]
    try:
        result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, timeout=480 if args.execution else 240)
        raw = result.stdout+result.stderr
        record.update(exit=result.returncode, status="passed" if result.returncode == 0 else "failed")
    except subprocess.TimeoutExpired as error:
        raw = (error.stdout or b"")+(error.stderr or b"")
        record.update(exit=124, status="timed-out")
    with log.open("xb") as out:
        out.write(raw)
    record.update(ended=stamp(), command=command, log_digest=sha(raw),
        cleanup="scenario finally blocks stop owned services/proxy and remove temporary keys; caller removes databases; inspect owned resources after timeout")
    args.output.write_text(json.dumps(record, indent=2)+"\n", encoding="utf-8")
    print(raw.decode(errors="replace"))
    print(f"Retained {record['status']} activation attempt: {args.output}")
    return record["exit"]


if __name__ == "__main__":
    raise SystemExit(main())
