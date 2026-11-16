#!/usr/bin/env python3
"""Export queued Epicbox messages from a MongoDB-backed Node relay as JSON Lines.

Output goes to stdout, one object per line, in the format read by
`epicmail import`. A summary goes to stderr. The script only reads.

The stock Node relay (app_mongo.js without the Postgres store) keeps waiting slates in
database `epicbox`, collection `slates`. A row has: queue (recipient public key, may carry
a domain), made (false until the wallet acknowledges), payload (BSON Binary holding the JSON
{"str","challenge","signature"}), replyto (sender address), createdat (Date), expiration,
messageid. The relay's TTL index drops rows older than 604800 s; --ttl applies the same cutoff.
Only rows with made:false are exported. This store has no forward queue, so no "forward"
records are written.

The script runs `mongosh --quiet --eval` with a find() and a sort(): no insert, update,
delete or drop. Nothing is written to the database and no file is written on the database
host. The `mongosh` binary must be installed where the script runs (pymongo is not needed).
The connection string may hold a password: it is passed to mongosh and never printed by
this script, and it is removed from mongosh error text.

Connection (--uri): default is the MONGO_URL environment variable, else
mongodb://127.0.0.1:27017/epicbox. --db (default epicbox) and --collection (default slates)
choose the collection.

Examples:
  tools/export-node-mongo.py > queued.jsonl
  MONGO_URL='mongodb://user:pass@127.0.0.1:27017/epicbox?authSource=admin' \
      tools/export-node-mongo.py > queued.jsonl
  tools/export-node-mongo.py --uri mongodb://10.0.0.5:27017 --db epicbox_floonet \
      --now 2026-05-01T00:00:00Z > queued.jsonl
  ssh relay-host 'python3 - --uri ...' < tools/export-node-mongo.py > queued.jsonl

Exit status: 0 all rows exported, 2 usage error, 3 mongosh failed, 4 some rows skipped.
"""

import argparse
import base64
import datetime
import json
import os
import re
import subprocess
import sys

DEFAULT_TTL = 7 * 24 * 3600  # the Node relay's TTL index drops rows older than this
DEFAULT_URI = "mongodb://127.0.0.1:27017/epicbox"
KEY_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{52}$")  # base58, 52 chars
NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,120}$")
NOW_RE = re.compile(r"^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?)?\s*(Z|[+-]\d{2}:?\d{2})?$")

# Prints one EJSON document per line. DB, COL and CUTOFF_MS are filled in as JSON literals.
JS = """
const c = db.getSiblingDB(%(db)s).getCollection(%(col)s);
const cur = c.find({made: false, createdat: {$gt: new Date(%(cutoff)d)}}).sort({createdat: 1});
cur.forEach(d => print(EJSON.stringify(d, {relaxed: false})));
"""


def die(msg, code=2):
    print(f"export-node-mongo: {msg}", file=sys.stderr)
    sys.exit(code)


def scrub(text, uri):
    """Remove the connection string, and the password inside it, from text."""
    text = text.replace(uri, "<uri>")
    m = re.match(r"^[a-z+]+://([^/@]*)@", uri)
    if m and ":" in m.group(1):
        pw = m.group(1).split(":", 1)[1]
        if pw:
            text = text.replace(pw, "***")
    return text


def parse_now(s):
    if s is None:
        return datetime.datetime.now(datetime.timezone.utc)
    s = s.strip().replace(" ", "T")
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        d = datetime.datetime.fromisoformat(s)
    except ValueError:
        die("--now must be an ISO timestamp")
    if d.tzinfo is None:
        d = d.replace(tzinfo=datetime.timezone.utc)
    return d


def ejson_millis(v):
    """Milliseconds since the epoch from an EJSON Date (canonical or relaxed)."""
    if isinstance(v, dict) and "$date" in v:
        v = v["$date"]
        if isinstance(v, dict) and "$numberLong" in v:
            return int(v["$numberLong"])
        if isinstance(v, (int, float)):
            return int(v)
        if isinstance(v, str):
            d = datetime.datetime.fromisoformat(v.replace("Z", "+00:00"))
            return int(d.timestamp() * 1000)
    raise ValueError("createdat is not a date")


def ejson_payload_bytes(v):
    """The payload bytes from an EJSON Binary (or, as a fallback, a plain string)."""
    if isinstance(v, dict) and "$binary" in v:
        b = v["$binary"]
        if isinstance(b, dict):
            b = b.get("base64")
        return base64.b64decode(b, validate=True)
    if isinstance(v, str):
        return v.encode("utf-8")
    raise ValueError("payload is not Binary")


class Mongo:
    def __init__(self, uri, mongosh):
        self.uri = uri
        self.mongosh = mongosh

    def find_waiting(self, db, col, cutoff_ms):
        js = JS % {"db": json.dumps(db), "col": json.dumps(col), "cutoff": cutoff_ms}
        cmd = [self.mongosh, "--quiet", "--norc", self.uri, "--eval", js]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True)
        except FileNotFoundError:
            die(f"{self.mongosh} not found: install mongosh or pass --mongosh", 3)
        if p.returncode != 0:
            die(f"mongosh failed: {scrub(p.stderr.strip(), self.uri)}", 3)
        return [ln for ln in p.stdout.splitlines() if ln.strip()]


def export(mongo, args, out, stats):
    now = parse_now(args.now)
    cutoff_ms = int((now.timestamp() - args.ttl) * 1000)
    for line in mongo.find_waiting(args.db, args.collection, cutoff_ms):
        stats["slate_rows"] += 1
        try:
            d = json.loads(line)
        except ValueError:
            stats["skipped_bad_payload"] += 1
            print("export-node-mongo: skip row: mongosh output is not JSON", file=sys.stderr)
            continue
        q = d.get("queue")
        queue = q.split("@", 1)[0] if isinstance(q, str) else ""
        if not KEY_RE.match(queue):
            stats["skipped_bad_queue"] += 1
            continue
        try:
            p = json.loads(ejson_payload_bytes(d.get("payload")).decode("utf-8"))
            s, sig = p["str"], p["signature"]
            if not isinstance(s, str) or not isinstance(sig, str):
                raise ValueError("str/signature not strings")
            created = ejson_millis(d.get("createdat")) // 1000
        except (ValueError, KeyError, TypeError) as e:  # UnicodeDecodeError is a ValueError
            stats["skipped_bad_payload"] += 1
            print(f"export-node-mongo: skip row queue={queue[:6]}..: {e}", file=sys.stderr)
            continue
        replyto = d.get("replyto")
        replyto = replyto if isinstance(replyto, str) else ""
        msgid = d.get("messageid")
        ch = p.get("challenge")
        rec = {
            "kind": "slate",
            "queue": queue,
            "from": replyto,
            "str": s,
            "signature": sig,
            "challenge": ch if isinstance(ch, str) else "",
            "messageid": msgid if isinstance(msgid, str) and msgid else None,
            "created_at": created,
            "expires_at": created + args.ttl,
            "deliveries": 0,  # the Node relay keeps no delivery counter
        }
        if not replyto:
            stats["no_from"] += 1
        out.write(json.dumps(rec, ensure_ascii=False, separators=(",", ":")) + "\n")
        stats["slate"] += 1
    stats["forward_table"] = "none (the Node relay on MongoDB keeps no forward queue)"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--uri", default=os.environ.get("MONGO_URL") or DEFAULT_URI,
                    help="MongoDB connection string (default: $MONGO_URL, else " + DEFAULT_URI + ")")
    ap.add_argument("--db", default="epicbox", help="database name (default: epicbox)")
    ap.add_argument("--collection", default="slates", help="collection name (default: slates)")
    ap.add_argument("--mongosh", default="mongosh", help="mongosh binary (default: mongosh)")
    ap.add_argument("--ttl", type=int, default=DEFAULT_TTL,
                    help="seconds a row lives from createdat (default 604800)")
    ap.add_argument("--now", help="treat this ISO timestamp as now (for tests on old dumps)")
    args = ap.parse_args()
    if args.ttl <= 0:
        die("--ttl must be positive")
    if not NAME_RE.match(args.db) or not NAME_RE.match(args.collection):
        die("--db and --collection may hold only letters, digits, _ . -")
    if args.now and not NOW_RE.match(args.now.strip()):
        die("--now must be an ISO timestamp")

    stats = dict(slate_rows=0, slate=0, forward_rows=0, forward=0, skipped_bad_queue=0,
                 skipped_bad_payload=0, skipped_bad_frame=0, no_from=0, forward_table="read")
    out = sys.stdout
    export(Mongo(args.uri, args.mongosh), args, out, stats)
    out.flush()
    print("export-node-mongo: " + json.dumps({"source": "node-mongo", **stats}), file=sys.stderr)
    skipped = stats["skipped_bad_queue"] + stats["skipped_bad_payload"] + stats["skipped_bad_frame"]
    sys.exit(4 if skipped else 0)


if __name__ == "__main__":
    main()
