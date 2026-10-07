#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run separate Stage 1 services and retain exact source/binary pins and test results."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

from run_stage1 import ROOT, sha, sources, stamp


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--opa", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--database", choices=("memory", "postgres"), default="memory")
    args = parser.parse_args()
    workspace = args.workspace.resolve(strict=True)
    suffix = ".exe" if os.name == "nt" else ""
    binaries = {name: workspace / name / ("server/target/debug" if name == "munarium" else "target/debug")
                / (("munarium-server" if name == "munarium" else name)+suffix)
                for name in ("munarium", "munarium-warden", "munarium-registry", "munarium-gate")}
    record = dict(started=stamp(), profile="stage1-services-v1", database=args.database, sources=sources(workspace),
                  binaries={name: sha(path.read_bytes()) for name, path in binaries.items()},
                  evaluator=sha(args.opa.read_bytes()), status="running", independent_review="pending")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as output:
        output.write(json.dumps(record, indent=2)+"\n")
    env = dict(os.environ, STAGE1_WORKSPACE=str(workspace), STAGE1_OPA=str(args.opa.resolve(strict=True)),
               MUNARIUM_PLATFORM_TEST_BINARY=str(binaries["munarium"]))
    if args.database == "postgres" and not env.get("MUNARIUM_PLATFORM_TEST_DATABASE_URL"):
        raise ValueError("explicit disposable PostgreSQL URL required")
    command = [sys.executable, "-m", "pytest", "tests/network/test_services.py", "-q", "--tb=short", "--assert=plain", "-k", args.database]
    try:
        result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, timeout=240)
        raw = result.stdout + result.stderr
        record.update(exit=result.returncode, status="passed" if result.returncode == 0 else "failed")
    except subprocess.TimeoutExpired as error:
        raw = (error.stdout or b"")+(error.stderr or b"")
        record.update(exit=124, status="timed-out")
    log = args.output.with_suffix(".log")
    with log.open("xb") as output:
        output.write(raw)
    record.update(ended=stamp(), command=command, log_digest=sha(raw),
                  cleanup="test finally blocks stop owned service processes and remove temporary key/config directories; inspect on timeout")
    args.output.write_text(json.dumps(record, indent=2)+"\n", encoding="utf-8")
    print(raw.decode(errors="replace"))
    print(f"Retained {record['status']} service attempt: {args.output}")
    return record["exit"]


if __name__ == "__main__":
    raise SystemExit(main())
