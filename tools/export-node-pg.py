#!/usr/bin/env python3
"""Export queued Epicbox messages from a Postgres-backed relay as JSON Lines.

Output goes to stdout, one object per line, in the format read by
`epicmail import`. A summary goes to stderr. The script only reads.

Sources (--source):
  node    The Node relay (app_mongo.js + pgstore.js): tables `slates` and
          `slates_forward`. Default.
  python  The Python `epic-relay`: table `slates` with `status`.

The script runs `psql` in a READ ONLY transaction and uses COPY ... TO STDOUT.
Connection settings come from the usual libpq variables (PGHOST, PGPORT,
PGUSER, PGDATABASE, PGPASSFILE) or from --dsn. Nothing is written to the
database and no file is written on the database host.

Examples:
  PGDATABASE=floonet_epicbox tools/export-node-pg.py > queued.jsonl
  tools/export-node-pg.py --dsn 'postgresql:///epic_relay?host=/var/run/postgresql' \
      --source python > queued-python.jsonl
  ssh relay-host 'cd /tmp && python3 - --dsn ...' < tools/export-node-pg.py
"""

import argparse
import csv
import io
import json
import os
import re
import subprocess
import sys

DEFAULT_TTL = 7 * 24 * 3600  # the Node relay's sweep removes rows older than this
KEY_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{52}$")  # base58, 52 chars


def die(msg, code=2):
    print(f"export-node-pg: {msg}", file=sys.stderr)
    sys.exit(code)


class Psql:
    def __init__(self, dsn, psql):
        self.dsn = dsn
        self.psql = psql

    def _run(self, args, stdin=None):
        cmd = [self.psql, "-X", "-q", "-v", "ON_ERROR_STOP=1"]
        if self.dsn:
            cmd += ["-d", self.dsn]
        cmd += args
        env = dict(os.environ)
        # Belt and braces: the session is read only even outside our own BEGIN.
        env["PGOPTIONS"] = (env.get("PGOPTIONS", "") + " -c default_transaction_read_only=on").strip()
        env["PGCLIENTENCODING"] = "UTF8"
        p = subprocess.run(cmd, input=stdin, capture_output=True, text=True, env=env)
        if p.returncode != 0:
            die(f"psql failed: {p.stderr.strip()}", 3)
        return p.stdout

    def scalar_lines(self, sql):
        out = self._run(["-A", "-t", "-c", sql])
        return [ln for ln in out.splitlines() if ln != ""]

    def copy_csv(self, select_sql):
        script = (
            "BEGIN READ ONLY ISOLATION LEVEL REPEATABLE READ;\n"
            f"COPY ({select_sql}) TO STDOUT WITH (FORMAT csv);\n"
            "COMMIT;\n"
        )
        out = self._run(["-f", "-"], stdin=script)
        return csv.reader(io.StringIO(out, newline=""))


def table_columns(db, table):
    rows = db.scalar_lines(
        "SELECT column_name FROM information_schema.columns "
        f"WHERE table_schema = 'public' AND table_name = '{table}'"
    )
    return set(rows)


def now_sql(now):
    if now is None:
        return "now()"
    return f"'{now}'::timestamptz"


def export_node(db, args, out, stats):
    cols = table_columns(db, "slates")
    if not cols:
        die("table public.slates not found: is this the Node relay database?")
    need = {"queue", "made", "payload", "replyto", "createdat", "messageid"}
    if need - cols:
        die(f"slates is missing columns {sorted(need - cols)}")
    deliveries = "deliveries" if "deliveries" in cols else "0"
    now = now_sql(args.now)
    ttl = args.ttl
    sel = (
        "SELECT queue, replyto, encode(payload, 'hex'), messageid, "
        f"EXTRACT(EPOCH FROM createdat)::bigint, {deliveries} "
        "FROM slates "
        f"WHERE NOT made AND createdat > {now} - interval '{ttl} seconds' "
        "ORDER BY createdat, id"
    )
    for q, replyto, payload_hex, msgid, created, deliv in db.copy_csv(sel):
        stats["slate_rows"] += 1
        queue = q.split("@", 1)[0]
        if not KEY_RE.match(queue):
            stats["skipped_bad_queue"] += 1
            continue
        try:
            p = json.loads(bytes.fromhex(payload_hex).decode("utf-8"))
            s, sig = p["str"], p["signature"]
            if not isinstance(s, str) or not isinstance(sig, str):
                raise ValueError("str/signature not strings")
        except (ValueError, KeyError, TypeError) as e:
            stats["skipped_bad_payload"] += 1
            print(f"export-node-pg: skip row queue={queue[:6]}..: {e}", file=sys.stderr)
            continue
        ch = p.get("challenge")
        created = int(created)
        rec = {
            "kind": "slate",
            "queue": queue,
            "from": replyto or "",
            "str": s,
            "signature": sig,
            "challenge": ch if isinstance(ch, str) else "",
            "messageid": msgid or None,
            "created_at": created,
            "expires_at": created + ttl,
            "deliveries": int(deliv),
        }
        if not replyto:
            stats["no_from"] += 1
        out.write(json.dumps(rec, ensure_ascii=False, separators=(",", ":")) + "\n")
        stats["slate"] += 1

    fcols = table_columns(db, "slates_forward")
    if not fcols:
        stats["forward_table"] = "absent (relay build before patch 0005)"
        return
    sel = (
        "SELECT target_host, target_port, encode(frame, 'hex'), attempts, "
        "EXTRACT(EPOCH FROM createdat)::bigint "
        "FROM slates_forward "
        f"WHERE state = 'queued' AND createdat > {now} - interval '{ttl} seconds' "
        "ORDER BY id"
    )
    for host, port, frame_hex, attempts, created in db.copy_csv(sel):
        stats["forward_rows"] += 1
        try:
            frame = bytes.fromhex(frame_hex).decode("utf-8")
            json.loads(frame)
        except (ValueError, UnicodeDecodeError):
            stats["skipped_bad_frame"] += 1
            continue
        rec = {
            "kind": "forward",
            "target_host": host,
            "target_port": int(port),
            "frame": frame,
            "attempts": int(attempts),
            "created_at": int(created),
        }
        out.write(json.dumps(rec, ensure_ascii=False, separators=(",", ":")) + "\n")
        stats["forward"] += 1


def export_python(db, args, out, stats):
    cols = table_columns(db, "slates")
    if "epicbox_msg_id" not in cols:
        die("slates has no epicbox_msg_id: is this the Python epic-relay database?")
    now = now_sql(args.now)
    # pending = never sent; delivered = sent, no Made yet. Both are still owed.
    sel = (
        "SELECT recipient_key, sender_address, encode(payload, 'hex'), signature, "
        "epicbox_msg_id, EXTRACT(EPOCH FROM created_at)::bigint, "
        "EXTRACT(EPOCH FROM expires_at)::bigint, attempts "
        "FROM slates "
        f"WHERE status IN ('pending', 'delivered') AND expires_at > {now} "
        "AND payload IS NOT NULL ORDER BY created_at, id"
    )
    for key, sender, payload_hex, sig, msgid, created, expires, attempts in db.copy_csv(sel):
        stats["slate_rows"] += 1
        queue = key.split("@", 1)[0]
        if not KEY_RE.match(queue):
            stats["skipped_bad_queue"] += 1
            continue
        try:
            s = bytes.fromhex(payload_hex).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            stats["skipped_bad_payload"] += 1
            continue
        rec = {
            "kind": "slate",
            "queue": queue,
            "from": sender,
            "str": s,
            "signature": sig,
            "challenge": "",  # the Python relay does not store it
            "messageid": msgid or None,
            "created_at": int(created),
            "expires_at": int(expires),
            "deliveries": int(attempts),
        }
        out.write(json.dumps(rec, ensure_ascii=False, separators=(",", ":")) + "\n")
        stats["slate"] += 1
    stats["forward_table"] = "none (the Python relay keeps no forward queue)"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--source", choices=["node", "python"], default="node")
    ap.add_argument("--dsn", help="libpq connection string or URI (default: libpq environment)")
    ap.add_argument("--psql", default="psql", help="psql binary (default: psql)")
    ap.add_argument("--ttl", type=int, default=DEFAULT_TTL,
                    help="Node source only: seconds a row lives from createdat (default 604800)")
    ap.add_argument("--now", help="treat this ISO timestamp as now (for tests on old dumps)")
    args = ap.parse_args()
    if args.now and not re.match(r"^[0-9T:+\-. Z]+$", args.now):
        die("--now must be an ISO timestamp")

    db = Psql(args.dsn, args.psql)
    stats = dict(slate_rows=0, slate=0, forward_rows=0, forward=0, skipped_bad_queue=0,
                 skipped_bad_payload=0, skipped_bad_frame=0, no_from=0, forward_table="read")
    out = sys.stdout
    if args.source == "node":
        export_node(db, args, out, stats)
    else:
        export_python(db, args, out, stats)
    out.flush()
    print("export-node-pg: " + json.dumps({"source": args.source, **stats}), file=sys.stderr)
    skipped = stats["skipped_bad_queue"] + stats["skipped_bad_payload"] + stats["skipped_bad_frame"]
    sys.exit(4 if skipped else 0)


if __name__ == "__main__":
    main()
