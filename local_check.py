#!/usr/bin/env python3
"""Build and serve a private subscription checked twice on this computer's network."""
import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

import build
import validate


ROOT = Path(__file__).resolve().parent
LOCAL_ROOT = ROOT / ".local-subscription"
PUBLIC_FILES = {"auto.json", "all.txt", "whitelist.txt", "regular.txt", "ai.txt", "ru_only.txt"}


def intersect_reports(first, second):
    for report in (first, second):
        if not build.fresh_probe_time(report.get("__meta__", {}).get("checked_at")):
            raise ValueError("Local probe is stale; run the check again")
    merged = {}
    for key, record in first.items():
        if key == "__meta__":
            continue
        repeat = second.get(key, {})
        if build.valid_probe_result(record) and build.valid_probe_result(repeat):
            merged[key] = {**repeat, "local_passes": 2,
                           "gemini": bool(record.get("gemini") and record.get("exit") == repeat.get("exit")),
                           "first_checked_at": first["__meta__"]["checked_at"]}
        else:
            merged[key] = {**record, "ok": False,
                           "local_passes": int(build.valid_probe_result(record)) + int(build.valid_probe_result(repeat)),
                           "local_reason": "not_confirmed_in_both_passes"}
    merged["__meta__"] = {**second["__meta__"], "scope": "local-network", "passes": 2}
    return merged


def make_server(folder, listen, port):
    folder = Path(folder).resolve()

    class Handler(BaseHTTPRequestHandler):
        def respond(self, body):
            name = unquote(urlsplit(self.path).path)
            if name not in {"/" + n for n in PUBLIC_FILES}:
                self.send_error(404)
                return
            path = folder / name[1:]
            if not path.resolve().is_relative_to(folder):
                self.send_error(404)
                return
            try:
                stats = json.loads((folder / "stats.json").read_text(encoding="utf-8"))
                proof = json.loads((folder / "local-proof.json").read_text(encoding="utf-8"))
                if (not build.fresh_probe_time(stats.get("last_successful_probe_at"))
                        or proof.get("scope") != "local-network" or proof.get("passes") != 2):
                    self.send_error(503, "Local checks expired; run local_check.py check again")
                    return
                data = path.read_bytes()
            except (OSError, ValueError):
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8" if name.endswith(".json") else "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("profile-title", "NordLine_Free WiFi")
            self.send_header("profile-update-interval", "1")
            self.send_header("ping-type", "proxy-head")
            self.send_header("check-url-via-proxy", build.TEST_URL)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if body:
                self.wfile.write(data)

        def do_GET(self):
            self.respond(True)

        def do_HEAD(self):
            self.respond(False)

        def log_message(self, *_):
            pass

    return ThreadingHTTPServer((listen, port), Handler)


def download_snapshot(folder):
    request = urllib.request.Request("https://api.github.com/repos/ALFiX01/NordLine_Free/git/ref/heads/main",
                                     headers={"User-Agent": "NordLine-Free-local-check"})
    with urllib.request.urlopen(request, timeout=30) as response:
        revision = json.load(response)["object"]["sha"]
    for name in ("all.txt", "whitelist.txt", "unverified.txt"):
        url = f"https://raw.githubusercontent.com/ALFiX01/NordLine_Free/{revision}/{name}"
        with urllib.request.urlopen(url, timeout=30) as response:
            (folder / name).write_bytes(response.read())
    return revision


def prepare_sources(source, work, excluded=()):
    def read(name):
        return [n for line in (source / name).read_text(encoding="utf-8").splitlines()
                if (n := build.parse_link(line))]
    primary, reserve = read("all.txt"), read("unverified.txt")
    whitelist = {build.probe_key(n) for n in read("whitelist.txt") + reserve}
    nodes = {build.probe_key(n): n for n in primary + reserve if build.probe_key(n) not in excluded}
    for name, selected in (("white-source.txt", [n for key, n in nodes.items() if key in whitelist]),
                            ("black-source.txt", [n for key, n in nodes.items() if key not in whitelist]),
                            ("combined.txt", list(nodes.values()))):
        (work / name).write_text("\n".join(n["raw"] for n in selected) + "\n", encoding="utf-8")
    return nodes


def check(args):
    for executable in (args.xray, args.mihomo):
        if not Path(executable).is_file():
            raise ValueError(f"Core binary not found: {executable}")
    local = Path(args.folder).resolve()
    local.mkdir(parents=True, exist_ok=True)
    # Keep run diagnostics private and separate from the files served to Happ.
    work = Path(tempfile.mkdtemp(prefix="check-", dir=local))
    source = Path(args.source_dir).resolve() if args.source_dir else work / "source"
    if args.source_dir:
        revision = "local-files"
    else:
        source.mkdir()
        revision = download_snapshot(source)
    exclusions_file = local / "client-exclusions.json"
    excluded = json.loads(exclusions_file.read_text(encoding="utf-8")) if exclusions_file.exists() else []
    if not isinstance(excluded, list) or any(not isinstance(key, str) or not key.startswith("v2:") for key in excluded):
        raise ValueError("client-exclusions.json must contain a JSON list of canonical v2 node keys")
    nodes = prepare_sources(source, work, set(excluded))
    if not nodes:
        raise ValueError("No candidates remain after client exclusions. Previous local files preserved")
    env = {**os.environ, "PYTHONUTF8": "1"}
    if args.curl:
        env["CURL_BIN"] = str(Path(args.curl).resolve())
    command = [sys.executable, "-X", "utf8", "-B", str(ROOT / "probe.py"), str(Path(args.xray).resolve()),
               str(ROOT / "build.py")]
    print(f"Local pass 1: {len(nodes)} nodes, {args.workers} workers", flush=True)
    subprocess.run(command + [str(work / "first.json"), str(work / "combined.txt"),
                             "--workers", str(args.workers)], env=env, check=True)
    first = json.loads((work / "first.json").read_text(encoding="utf-8"))
    candidates = [n for key, n in nodes.items() if build.valid_probe_result(first.get(key, {}))]
    if not candidates:
        raise ValueError("No nodes passed the first local check. Previous local files preserved")
    (work / "repeat.txt").write_text("\n".join(n["raw"] for n in candidates) + "\n", encoding="utf-8")
    print(f"Local pass 2: rechecking {len(candidates)} candidates", flush=True)
    subprocess.run(command + [str(work / "second.json"), str(work / "repeat.txt"), "--workers", str(args.workers),
                             "--skip-gemini"], env=env, check=True)
    second = json.loads((work / "second.json").read_text(encoding="utf-8"))
    merged = intersect_reports(first, second)
    merged["__meta__"]["source_revision"] = revision
    (work / "probe.json").write_text(json.dumps(merged, ensure_ascii=False, indent=2), encoding="utf-8")
    staging = work / "output"
    subprocess.run([sys.executable, "-X", "utf8", "-B", str(ROOT / "build.py"),
                    "white-source.txt,black-source.txt=bl", str(staging), "--alive", str(work / "probe.json")],
                   cwd=work, env=env, check=True)
    profiles = validate.validate_output(staging, require_probe=True)
    validate.check_cores(staging, profiles, args.xray, args.mihomo)
    # Publish only complete, validated files. os.replace is atomic per file.
    current = local / "current"
    current.mkdir(exist_ok=True)
    for name in PUBLIC_FILES | {"stats.json", "health.json"}:
        temporary = current / (name + ".tmp")
        shutil.copyfile(staging / name, temporary)
        os.replace(temporary, current / name)
    (current / "local-proof.json").write_text(json.dumps(merged["__meta__"], indent=2), encoding="utf-8")
    stats = json.loads((current / "stats.json").read_text(encoding="utf-8"))
    print(f"Local subscription ready: {stats['после дедупа']} nodes passed both checks. Files: {current}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("check")
    scan.add_argument("--xray", required=True)
    scan.add_argument("--mihomo", required=True)
    scan.add_argument("--curl")
    scan.add_argument("--source-dir")
    scan.add_argument("--folder", default=str(LOCAL_ROOT))
    scan.add_argument("--workers", type=int, default=8, choices=range(1, 49), metavar="1..48")
    serve = sub.add_parser("serve")
    serve.add_argument("--folder", default=str(LOCAL_ROOT / "current"))
    serve.add_argument("--listen", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    if args.command == "check":
        check(args)
    else:
        server = make_server(args.folder, args.listen, args.port)
        print(f"Serving verified files on {args.listen}:{server.server_port}", flush=True)
        if args.listen == "0.0.0.0":
            for address in socket.gethostbyname_ex(socket.gethostname())[2]:
                print(f"Happ URL: http://{address}:{server.server_port}/auto.json", flush=True)
        try:
            server.serve_forever()
        finally:
            server.server_close()


if __name__ == "__main__":
    main()
