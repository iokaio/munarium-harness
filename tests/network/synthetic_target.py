# SPDX-License-Identifier: Apache-2.0
"""Disposable independently persisted target. Never accepts a real release destination."""
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sqlite3
import ssl
import sys
import time


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def run(path):
    config = json.loads(Path(path).read_bytes())
    secret = Path(config["credential_file"]).read_bytes()
    database = config["database"]
    with sqlite3.connect(database) as db:
        db.executescript("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;"
            "CREATE TABLE IF NOT EXISTS state(id INTEGER PRIMARY KEY,epoch INTEGER,version INTEGER,digest TEXT);"
            "CREATE TABLE IF NOT EXISTS effects(operation TEXT PRIMARY KEY,receipt TEXT);"
            "CREATE TABLE IF NOT EXISTS sends(id INTEGER PRIMARY KEY,operation TEXT);")
        db.execute("CREATE TABLE IF NOT EXISTS rejections(id INTEGER PRIMARY KEY,reason TEXT)")
        db.execute("INSERT OR IGNORE INTO state VALUES(1,1,1,?)", (config["initial_digest"],))

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            try:
                self.process()
            except (ValueError, KeyError, TypeError, sqlite3.Error):
                self.reply(403, {"error": "refused"})

        def reply(self, status, body):
            raw = canonical(body)
            self.send_response(status)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(raw)

        def process(self):
            peer = hashlib.sha256(self.connection.getpeercert(binary_form=True)).hexdigest()
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 65536:
                raise ValueError()
            body = json.loads(self.rfile.read(length))
            with sqlite3.connect(database, timeout=2) as db:
                db.execute("BEGIN IMMEDIATE")
                epoch, version, digest = db.execute("SELECT epoch,version,digest FROM state WHERE id=1").fetchone()
                if self.path == "/observe" and peer in config["readers"]:
                    effects = [json.loads(r[0]) for r in db.execute("SELECT receipt FROM effects ORDER BY operation")]
                    return self.reply(200, dict(epoch=epoch, version=version, digest=digest, effects=effects,
                        rejections=[r[0] for r in db.execute("SELECT reason FROM rejections ORDER BY id")],
                        sends=db.execute("SELECT COUNT(*) FROM sends").fetchone()[0]))
                if self.path == "/floor" and peer == config["recovery_peer"]:
                    if type(body["epoch"]) is not int or body["epoch"] <= epoch:
                        raise ValueError()
                    db.execute("UPDATE state SET epoch=? WHERE id=1", (body["epoch"],))
                    db.commit()
                    return self.reply(200, dict(epoch=body["epoch"]))
                if self.path != "/effect" or peer != config["connector"] or not hmac.compare_digest(self.headers.get("Authorization", "").encode(), b"Bearer "+secret):
                    raise ValueError()
                request, admission = body["request"], body["admission"]
                p = admission["send_intent"]["payload"]
                operation = request["operation"]["id"]
                db.execute("INSERT INTO sends(operation) VALUES(?)", (operation,))
                db.commit()
                db.execute("BEGIN IMMEDIATE")
                epoch, version, digest = db.execute("SELECT epoch,version,digest FROM state WHERE id=1").fetchone()
                expected_digest = "sha256:"+hashlib.sha256(b"munarium:stage2:action-request:v1\0"+canonical(request)).hexdigest()
                if p["recovery_epoch"] != epoch:
                    db.execute("INSERT INTO rejections(reason) VALUES('recovery-floor')")
                    db.commit()
                    return self.reply(403, {"error": "recovery-floor"})
                if (admission["send_permitted"] is not True or p["request_digest"] != expected_digest
                        or p["operation"] != request["operation"] or p["target"] != config["target"]
                        or p["effect_key"] != operation or p["recovery_epoch"] != epoch or p["worker_fence"] != 1
                        or request["intent"]["environment"] != "disposable"
                        or request["intent"]["capability_operation"] != "release.publish_approved_artifact"
                        or request["intent"]["parameters"]["destination"] != "synthetic-release"
                        or request["intent"]["target_precondition"] != dict(version=version, content_digest=digest)
                        or time.time()+2 >= admission["expires_at"]
                        or db.execute("SELECT 1 FROM effects WHERE operation=?", (operation,)).fetchone()):
                    raise ValueError()
                receipt = dict(operation=request["operation"], request_digest=expected_digest, target=config["target"],
                    effect_key=operation, recovery_epoch=epoch, worker_fence=1, version=version+1,
                    content_digest=request["intent"]["parameters"]["artifact_digest"], status="completed")
                db.execute("INSERT INTO effects VALUES(?,?)", (operation, canonical(receipt).decode()))
                db.execute("UPDATE state SET version=?,digest=? WHERE id=1", (receipt["version"], receipt["content_digest"]))
                db.commit()
                if body.get("lose_reply"):
                    self.close_connection = True
                    return
                self.reply(200, receipt)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(config["certificate"], config["key"])
    context.load_verify_locations(cafile=config["ca"])
    context.verify_mode = ssl.CERT_REQUIRED
    server = ThreadingHTTPServer(("127.0.0.1", config["port"]), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    run(sys.argv[1])
