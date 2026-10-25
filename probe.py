#!/usr/bin/env python3
"""Probe VLESS nodes through Xray. Optional env: GEMINI_API_KEY, CURL_BIN.

python probe.py <xray_bin> <build.py> <out.json> <file1> [file2 ...]
"""
import importlib.util
import argparse
import json
import math
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from build import TEST_URL, PROBE_POLICY


TARGETS = (
    (TEST_URL, "204-head"),
    ("https://www.cloudflare.com/cdn-cgi/trace", "trace"),
    ("https://www.msftconnecttest.com/connecttest.txt", "microsoft"),
)
BLOCK_MARKERS = ("location is not supported", "isn't currently supported", "not supported in your country",
                 "not available in your country", "isn’t currently supported")


def via(port, args):
    command = [os.environ.get("CURL_BIN", "curl"), "-sSL", "--socks5-hostname", f"127.0.0.1:{port}",
               "--noproxy", "", "--connect-timeout", "5", "-m", "10",
               "-w", "\n%{http_code} %{time_total} %{url_effective}"] + args
    result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15)
    if result.returncode:
        raise ValueError(f"curl_exit_{result.returncode}")
    body, _, tail = result.stdout.rpartition("\n")
    fields = tail.split(" ", 2)
    ms = float(fields[1]) * 1000
    if not math.isfinite(ms) or ms < 0:
        raise ValueError("invalid_latency")
    return fields[0], fields[2] if len(fields) > 2 else "", body, int(ms)


def check_connectivity(port):
    failures = []
    last_checks = []
    for attempt in range(2):
        checks = []
        exit_country = None
        for url, kind in TARGETS:
            method = "HEAD" if kind == "204-head" else "GET"
            check = {"url": url, "method": method, "ok": False}
            checks.append(check)
            try:
                code, _, body, ms = via(port, (["-I"] if method == "HEAD" else []) + [url])
                loc = next((line[4:].strip().upper() for line in body.splitlines() if line.startswith("loc=")), None)
                valid_loc = bool(loc and len(loc) == 2 and loc.isascii() and loc.isalpha())
                success = ((kind == "trace" and code == "200" and valid_loc)
                           or (kind == "204-head" and code == "204")
                           or (kind == "microsoft" and code == "200" and body.strip() == "Microsoft Connect Test"))
                if success:
                    check.update(ok=True, ms=ms)
                    if kind == "trace":
                        exit_country = loc
                    if checks[0]["ok"] and sum(c["ok"] for c in checks) >= 2:
                        return {"ok": True, "ms": checks[0]["ms"], "exit": exit_country,
                                "endpoint": TEST_URL, "policy": PROBE_POLICY,
                                "checks": checks, "failed_targets": failures}
                    continue
                reason = f"unexpected_http_{code}_or_body"
            except (ValueError, IndexError, OSError, subprocess.TimeoutExpired) as exc:
                reason = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
            failures.append({"url": url, "attempt": attempt + 1, "reason": reason})
            if method == "HEAD":
                break  # No secondary success can compensate for a failed client probe.
        last_checks = checks
    return {"ok": False, "policy": PROBE_POLICY, "checks": last_checks, "failed_targets": failures}


def gemini_ok(port):
    key = os.environ.get("GEMINI_API_KEY", "").strip()
    try:
        if key:
            code, _, body, _ = via(port, ["-H", "Content-Type: application/json", "-d",
                                        json.dumps({"contents": [{"parts": [{"text": "ok"}]}]}),
                                        "https://generativelanguage.googleapis.com/v1beta/models/"
                                        f"gemini-flash-latest:generateContent?key={key}"])
            return not any(m in body.lower() for m in BLOCK_MARKERS) and code in ("200", "429")
        code, _, body, _ = via(port, ["https://generativelanguage.googleapis.com/v1beta/models?key=invalid"])
        if any(m in body.lower() for m in BLOCK_MARKERS) or code not in ("200", "400", "401", "403"):
            return False
        code, url, body, _ = via(port, ["https://gemini.google.com/app"])
        return code == "200" and "google.com" in url and not any(m in body.lower() for m in BLOCK_MARKERS)
    except (ValueError, IndexError, OSError, subprocess.TimeoutExpired):
        return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("xray_bin")
    parser.add_argument("build_py")
    parser.add_argument("out_json")
    parser.add_argument("files", nargs="+")
    parser.add_argument("--workers", type=int, default=48, choices=range(1, 49), metavar="1..48")
    parser.add_argument("--skip-gemini", action="store_true")
    args = parser.parse_args()
    xray_bin, build_py, out_json, files = args.xray_bin, args.build_py, args.out_json, args.files
    spec = importlib.util.spec_from_file_location("builder", build_py)
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    nodes, seen = [], set()
    for path in files:
        with open(path, encoding="utf-8") as source:
            for line in source:
                n = builder.parse_link(line)
                if not n or n["host"] in ("0.0.0.0", "127.0.0.1") or n["uuid"] == "warning" or n["sec"] == "none":
                    continue
                key = builder.probe_key(n)
                if key not in seen:
                    seen.add(key)
                    n["key"] = key
                    nodes.append(n)
    base = 31000
    cfg = {"log": {"loglevel": "none"}, "inbounds": [], "outbounds": [], "routing": {"rules": []}}
    for i, n in enumerate(nodes):
        cfg["inbounds"].append({"tag": f"in{i}", "listen": "127.0.0.1", "port": base + i,
                                "protocol": "socks", "settings": {"udp": False}})
        cfg["outbounds"].append(builder.xray_outbound(n, f"out{i}"))
        cfg["routing"]["rules"].append({"type": "field", "inboundTag": [f"in{i}"], "outboundTag": f"out{i}"})
    cfg["outbounds"].append({"tag": "direct", "protocol": "freedom"})
    proc = subprocess.Popen([xray_bin, "run", "-c", "stdin:"], stdin=subprocess.PIPE,
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        proc.stdin.write(json.dumps(cfg).encode("utf-8"))
        proc.stdin.close()
        time.sleep(3)
        if proc.poll() is not None:
            raise RuntimeError("Xray failed: " + proc.stderr.read().decode(errors="replace")[:800])

        def test(i):
            result = check_connectivity(base + i)
            if result["ok"]:
                country = result.get("exit") or nodes[i]["cc"]
                if not args.skip_gemini:
                    result["gemini"] = gemini_ok(base + i) if country not in builder.NO_AI else False
            return nodes[i]["key"], result

        report = {}
        with ThreadPoolExecutor(args.workers) as pool:
            futures = [pool.submit(test, i) for i in range(len(nodes))]
            for future in as_completed(futures):
                key, result = future.result()
                report[key] = result
                if len(report) % args.workers == 0 or len(report) == len(nodes):
                    print(f"Progress {len(report)}/{len(nodes)}, reachable {sum(bool(r['ok']) for r in report.values())}", flush=True)
    finally:
        proc.terminate()
        proc.wait(timeout=10)
        proc.stderr.close()
    ok = sum(1 for r in report.values() if r["ok"])
    gemini = sum(1 for r in report.values() if r.get("gemini"))
    report["__meta__"] = {"checked_at": datetime.now(timezone.utc).isoformat()}
    with open(out_json, "w", encoding="utf-8") as output:
        json.dump(report, output, ensure_ascii=False, indent=2)
    gemini_summary = "not checked" if args.skip_gemini else str(gemini)
    print(f"Checked {len(nodes)}, reachable {ok}, Gemini {gemini_summary}")


if __name__ == "__main__":
    main()
