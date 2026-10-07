#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the bounded Stage 1 composition and retain an experimental record."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "tests/composition/Cargo.lock"


def stamp():
    return datetime.now(timezone.utc).isoformat()


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def sources(workspace):
    pins = {}
    for name in ("munarium", "munarium-platform", "munarium-registry", "munarium-warden", "munarium-gate", "munarium-harness"):
        path = workspace / name
        git = ["git", "-c", f"safe.directory={path.as_posix()}", "-C", str(path)]
        def read(*args):
            return subprocess.check_output(git + list(args), stderr=subprocess.DEVNULL)
        remote = read("remote", "get-url", "origin").decode().strip()
        if remote not in {f"https://github.com/iokaio/{name}", f"https://github.com/iokaio/{name}.git"}:
            raise ValueError(f"unexpected repository: {name}")
        files = read("ls-files", "-z", "--cached", "--others", "--exclude-standard").decode().split("\0")
        inventory = {}
        for relative in sorted(set(files)):
            if relative and not relative.startswith(".worktrees/"):
                file = path / relative
                inventory[relative] = sha(file.read_bytes()) if file.is_file() else "deleted"
        pins[name] = dict(repository=remote, revision=read("rev-parse", "HEAD").decode().strip(),
                          dirty=bool(read("status", "--porcelain").strip()),
                          tree_digest=sha(json.dumps(inventory, sort_keys=True).encode()))
    return pins


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--workspace", type=Path, required=True)
    p.add_argument("--opa", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--database", choices=("memory", "postgres"), default="memory")
    p.add_argument("--database-image", help="Operator-observed immutable database image reference")
    p.add_argument("--database-version", help="Operator-observed database version; never a connection URL")
    p.add_argument("--owner", required=True)
    p.add_argument("--online", action="store_true", help="Fetch locked public crates")
    p.add_argument("--refresh-lock", action="store_true", help="Explicitly regenerate the reviewable composition lock")
    p.add_argument("--prior-attempt")
    p.add_argument("--toolchain", default="1.98.1", help="Installed rustup alias; actual compiler must be 1.98.1")
    args = p.parse_args()
    if not args.owner.strip():
        raise ValueError("a supplied operator or owner role is required")
    workspace = args.workspace.resolve(strict=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    artifacts = args.output.with_suffix(".artifacts")
    if args.output.exists() or artifacts.exists():
        raise ValueError("refusing to replace prior run evidence")
    with args.output.open("x", encoding="utf-8") as out:
        out.write("{}\n")
    artifacts.mkdir()
    exclusions = ["S1 platform authority profile", "REST/gRPC platform admission", "provider enrollment",
                  "network isolation qualification", "execution", "Matrix", "release qualification"]
    record = dict(schema_version=1, run_id="stage1-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"),
                  started=stamp(), ended=None, owner=args.owner, stage=1, status="running",
                  boundary="in-process decision-only libraries; bounded native OPA worker", exclusions=exclusions,
                  qualification=False, review=dict(status="pending", reviewer=None, independence="same implementer"),
                  sources={}, commands=[], cases=[], gaps=[], artifacts=[], prior_attempt=args.prior_attempt,
                  contracts=dict(status="proposed; human acceptance pending", accepted_adr_revisions=[]),
                  environment=dict(os=platform.platform(), python=platform.python_version(), database=args.database,
                                   database_image=args.database_image, database_version=args.database_version,
                                   topology="one process; privileged adapters; native worker; optional loopback PostgreSQL",
                                   deny_edges="capability refusals; network isolation not measured",
                                   resource_ceiling=dict(opa_process_bytes=67108864, opa_deadline_ms=100),
                                   observed_resource_use=None, owner=args.owner, cost_authority="operator-requested local tests",
                                   expiry="temporary consumer removed on exit; caller owns database teardown"),
                  retention=dict(access="local synthetic evidence", expiry="operator-defined", cleanup="pending"))
    def retain():
        args.output.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    def artifact(name, raw):
        (artifacts / name).write_bytes(raw)
        record["artifacts"].append(dict(path=name, digest=sha(raw), bytes=len(raw), access="synthetic-local"))
    def command(argv, cwd, env):
        started = stamp()
        try:
            result = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, timeout=600)
        except subprocess.TimeoutExpired as error:
            result = subprocess.CompletedProcess(argv, 124, error.stdout or b"", error.stderr or b"")
        i = len(record["commands"])
        artifact(f"command-{i}.stdout", result.stdout)
        artifact(f"command-{i}.stderr", result.stderr)
        record["commands"].append(dict(command=argv, cwd="temporary integration consumer", started=started,
                                       ended=stamp(), exit=result.returncode, stdout_digest=sha(result.stdout), stderr_digest=sha(result.stderr)))
        retain()
        if result.returncode:
            raise RuntimeError(f"composition failed; retained command-{i}.stderr")
        print(f"Passed: {' '.join(argv)}", flush=True)
        return result.stdout.decode("utf-8")
    retain()
    try:
        record["sources"] = sources(workspace)
        env = dict(os.environ)
        env["RUSTUP_TOOLCHAIN"] = args.toolchain
        env["CARGO_TARGET_DIR"] = str(ROOT / "target/stage1-composition")
        env["STAGE1_WORKSPACE"] = str(workspace)
        env["STAGE1_OPA"] = str(args.opa.resolve(strict=True))
        env["STAGE1_PYTHON"] = sys.executable
        if args.database == "memory":
            env.pop("MUNARIUM_TEST_DATABASE_URL", None)
        elif not env.get("MUNARIUM_TEST_DATABASE_URL"):
            raise ValueError("postgres profile requires explicit isolated MUNARIUM_TEST_DATABASE_URL")
        elif not args.database_image or "@sha256:" not in args.database_image or not args.database_version:
            raise ValueError("postgres profile requires observed database image/version metadata")
        gate = workspace / "munarium-gate"
        sys.path.insert(0, str(gate / "scripts"))
        from check_opa import capabilities, PIN
        if sha(args.opa.read_bytes()) != PIN:
            raise ValueError("OPA pin")
        caps = capabilities(args.opa)
        record["evaluator"] = dict(name="opa", version="1.21.1", executable_digest=PIN,
                                  worker_digest=sha((gate / "scripts/opa_worker.py").read_bytes()),
                                  capabilities_digest=sha(b"munarium:opa-capabilities:v1\0" + json.dumps(caps, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()))
        record["toolchain"] = subprocess.check_output(["rustc", "--version"], env=env, text=True).strip()
        if not record["toolchain"].startswith("rustc 1.98.1 "):
            raise ValueError("composition requires rustc 1.98.1")
        record["fixture"] = dict(generator_digest=sha((ROOT / "tests/composition/scenario.rs").read_bytes()),
                                seed="OS random ephemeral key; private material never retained",
                                target_initial_state="no target provisioned; execution capabilities absent")
        for name, path in {"hub": workspace / "munarium-platform/docs/decisions/candidates",
                           "gate": gate / "contracts/stage1", "registry": workspace / "munarium-registry/contracts/registry-v2",
                           "harness": ROOT / "contracts/stage1"}.items():
            record["contracts"][name] = {f.name: sha(f.read_bytes().replace(b"\r\n", b"\n")) for f in path.glob("*.json")}
        with tempfile.TemporaryDirectory(prefix="munarium-stage1-") as directory:
            work = Path(directory)
            (work / "src").mkdir()
            dependencies = {"munarium-harness": ROOT, "munarium-gate": gate,
                            "munarium-warden": workspace / "munarium-warden/identity-core", "munarium-registry": workspace / "munarium-registry",
                            "munarium-core": workspace / "munarium/server/src/munarium-core",
                            "munarium-store-mem": workspace / "munarium/server/src/munarium-store-mem",
                            "munarium-store-pg": workspace / "munarium/server/src/munarium-store-pg"}
            manifest = '[package]\nname="stage1-composition"\nversion="0.0.0"\nedition="2024"\npublish=false\n[dependencies]\n'
            for name, path in dependencies.items():
                package = 'package="munarium-warden-identity",' if name == "munarium-warden" else ''
                if name in {"munarium-registry", "munarium-gate"}:
                    package += 'default-features=false,'
                manifest += f'{name}={{{package}path={json.dumps(path.as_posix())}}}\n'
            manifest += 'serde_json="=1.0.149"\nsha2="=0.10.9"\nbase64="=0.22.1"\ned25519-dalek="=2.2.0"\ngetrandom="=0.3.4"\ntokio={version="=1.53.1",features=["rt-multi-thread"]}\n'
            manifest += '[[bin]]\nname="identity-interop"\npath=' + json.dumps((workspace / "munarium-registry/tests/interop/warden.rs").as_posix()) + '\n'
            env["REGISTRY_IDENTITY_VECTORS"] = str(workspace / "munarium-registry/contracts/identity-v1/identity-vectors.json")
            (work / "Cargo.toml").write_text(manifest, encoding="utf-8")
            (work / "src/main.rs").write_bytes((ROOT / "tests/composition/scenario.rs").read_bytes())
            (work / "capabilities.json").write_text(json.dumps(caps), encoding="utf-8")
            env["STAGE1_CAPABILITIES"] = str(work / "capabilities.json")
            if args.refresh_lock:
                command(["cargo", "generate-lockfile"] + ([] if args.online else ["--offline"]), work, env)
                LOCK.write_bytes((work / "Cargo.lock").read_bytes())
                record["sources"] = sources(workspace)
            else:
                shutil.copyfile(LOCK, work / "Cargo.lock")
            artifact("Cargo.lock", (work / "Cargo.lock").read_bytes())
            if args.online:
                command(["cargo", "fetch", "--locked"], work, env)
            command(["cargo", "run", "--offline", "--locked", "--bin", "identity-interop"], work, env)
            result = command(["cargo", "run", "--offline", "--locked", "--bin", "stage1-composition"], work, env)
            lines = [line for line in result.splitlines() if line.startswith("STAGE1_RESULT ")]
            evidence = [line for line in result.splitlines() if line.startswith("STAGE1_EVIDENCE ")]
            if len(lines) != 1 or len(evidence) != 1:
                raise ValueError("missing or ambiguous evidence")
            record["cases"] = json.loads(lines[0].removeprefix("STAGE1_RESULT "))
            record["cases"].append(dict(id="Registry-Warden-32-unchanged-vectors", result="passed"))
            record["durability"] = json.loads(evidence[0].removeprefix("STAGE1_EVIDENCE "))
            if not record["cases"] or any(c["result"] != "passed" for c in record["cases"]):
                raise ValueError("failed assertions")
            record["status"] = "passed"
    except Exception as error:
        record["status"] = "failed"
        record["gaps"].append(dict(status="failed", reason=type(error).__name__, owner=args.owner))
        raise
    finally:
        record["ended"] = stamp()
        record["gaps"].extend(dict(status="unavailable", reason=gap, owner=args.owner) for gap in exclusions)
        record["retention"]["cleanup"] = "temporary consumer removed; build cache and evidence retained; caller owns database teardown"
        retain()
    print(f"Passed {len(record['cases'])} experimental cases; record: {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
