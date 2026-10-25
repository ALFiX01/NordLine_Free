#!/usr/bin/env python3
"""Validate staged subscriptions before publication; never modify published files."""
import argparse
import ipaddress
import json
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import yaml

import build


def outbound_key(outbound):
    return json.dumps({k: v for k, v in outbound.items() if k != "tag"}, sort_keys=True)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_nodes(path):
    lines = [l.strip() for l in path.read_text(encoding="utf-8").splitlines()
             if l.strip() and not l.startswith("#")]
    nodes = [build.parse_link(l) for l in lines]
    require(all(nodes), f"{path.name}: invalid subscription entry")
    return nodes


def validate_output(folder, previous=None, require_probe=False):
    folder = Path(folder)
    lists = {name: read_nodes(folder / f"{name}.txt")
             for name in ("all", "whitelist", "regular", "ai", "ru_only")}
    reserve = read_nodes(folder / "unverified.txt")
    require(lists["all"], "all.txt: empty subscription")
    require(lists["whitelist"], "whitelist.txt: empty subscription")
    require(lists["regular"], "regular.txt: empty subscription")
    all_links = {n["raw"] for n in lists["all"]}
    require(len(all_links) == len(lists["all"]), "all.txt: duplicate entries")
    identities = {build.dedup_key(n) for n in lists["all"]}
    require(len(identities) == len(all_links), "all.txt: duplicate connections")
    for name, nodes in lists.items():
        require(all(n["raw"] in all_links for n in nodes), f"{name}.txt: unknown connection")
    reserve_keys = {build.probe_key(n) for n in reserve}
    primary_keys = {build.probe_key(n) for n in lists["all"]}
    require(not reserve_keys & primary_keys, "unverified.txt: overlaps verified subscription")
    require(len(reserve_keys) == len(reserve), "unverified.txt: duplicate connections")
    health = json.loads((folder / "health.json").read_text(encoding="utf-8"))
    expected_primary, expected_reserve = {}, {}
    for nodes, expected, status in ((lists["all"], expected_primary, "verified"),
                                    (reserve, expected_reserve, "unverified")):
        for n in nodes:
            record = health.get(build.probe_key(n), {})
            require(record.get("status") == status, "health.json: missing or wrong node status")
            if status == "verified":
                require(record.get("ok") is True and build.fresh_probe_time(record.get("checked_at")),
                        "health.json: missing fresh successful probe")
                require(isinstance(record.get("ms"), (int, float)) and not isinstance(record["ms"], bool)
                        and 0 <= record["ms"] < float("inf"), "health.json: invalid latency")
            n["insecure"] = record.get("insecure", False)
            expected[outbound_key(build.xray_outbound(n, ""))] = record
    stats = json.loads((folder / "stats.json").read_text(encoding="utf-8"))
    for key, name in (("после дедупа", "all"), ("ИИ", "ai"),
                      ("обычные блокировки", "regular"), ("РФ", "ru_only")):
        require(stats.get(key) == len(lists[name]), f"stats.json: count mismatch for {name}.txt")
    require(stats.get("непроверенный резерв") == len(reserve), "stats.json: reserve count mismatch")
    generated = datetime.fromisoformat(stats["generated_at"])
    require(generated.tzinfo is not None, "stats.json: generated_at needs timezone")
    if require_probe:
        checked = stats.get("last_successful_probe_at")
        require(checked, "probe: no successful live check")
        checked = datetime.fromisoformat(checked)
        require(checked.tzinfo is not None, "probe: check time needs timezone")
        age = (datetime.now(timezone.utc) - checked).total_seconds()
        require(-300 <= age <= 7200, "probe: successful check is stale or in the future")
    if previous and (Path(previous) / "all.txt").exists():
        old_count = len(read_nodes(Path(previous) / "all.txt"))
        # First migration: the old subscription mixed verified and unverified
        # nodes. Compare retained total once; later compare verified nodes only.
        retained = len(lists["all"]) if (Path(previous) / "health.json").exists() else len(lists["all"]) + len(reserve)
        require(retained >= old_count * 0.5,
                f"all.txt: fewer than 50% of previous nodes ({retained}/{old_count})")

    profiles = json.loads((folder / "auto.json").read_text(encoding="utf-8"))
    require(isinstance(profiles, list) and profiles, "auto.json: empty profile list")
    require(stats.get("конфигов в auto.json") == len(profiles), "auto.json: count mismatch")
    singles = [p for p in profiles if not p.get("routing", {}).get("balancers")]
    require(len(singles) == len(lists["all"]), "auto.json: missing individual profiles")
    reserve_profiles = json.loads((folder / "unverified.json").read_text(encoding="utf-8"))
    require(isinstance(reserve_profiles, list) and len(reserve_profiles) == len(reserve),
            "unverified.json: reserve count mismatch")
    require(all(not p.get("routing", {}).get("balancers") and "burstObservatory" not in p for p in reserve_profiles),
            "unverified.json: reserve must contain only manual profiles")
    for cfg in profiles:
        dns = cfg.get("dns", {})
        require(dns.get("servers"), "auto.json: missing DNS servers for Happ")
        first = dns["servers"][0]
        address = first.get("address") if isinstance(first, dict) else first
        require(isinstance(address, str) and address, "auto.json: invalid DNS address")
        if address.startswith("https://"):
            host = urlsplit(address).hostname
            address = dns.get("hosts", {}).get(host, host)
        if isinstance(address, list):
            address = address[0] if address else ""
        try:
            ipaddress.ip_address(address)
        except ValueError:
            raise ValueError("auto.json: DNS must resolve to an explicit IP for Happ") from None
        outs = {o["tag"]: o for o in cfg["outbounds"]}
        latencies = {}
        for tag, outbound in outs.items():
            if outbound["protocol"] == "vless":
                key = outbound_key(outbound)
                require(key in expected_primary, "auto.json: outbound has no verified health record")
                latencies[tag] = expected_primary[key]["ms"]
        for bal in cfg.get("routing", {}).get("balancers", []):
            tag = bal.get("fallbackTag", "")
            require(tag in outs and outs[tag]["protocol"] == "vless"
                    and any(tag.startswith(s) for s in bal["selector"]),
                    "auto.json: missing or ineligible balancer fallback")
            eligible = [t for t in latencies if any(t.startswith(s) for s in bal["selector"])]
            require(latencies[tag] == min(latencies[t] for t in eligible),
                    "auto.json: fallback does not use the best measured latency in its group")
    for cfg in reserve_profiles:
        require(all(outbound_key(o) in expected_reserve for o in cfg["outbounds"] if o["protocol"] == "vless"),
                "unverified.json: unknown reserve outbound")

    for mode in ("regular", "whitelist"):
        cfg = yaml.safe_load((folder / f"clash_{mode}.yaml").read_text(encoding="utf-8"))
        names = {p["name"] for p in cfg["proxies"]}
        require(names <= {n["frag"] for n in lists["all"]}, f"clash_{mode}.yaml: unverified proxy")
        allowed = {n["frag"] for n in lists[mode]}
        # Regular export also offers Russian/manual groups; whitelist must never
        # offer regular-only nodes, even for its AI domain rules.
        if mode == "whitelist":
            require(names <= allowed, "clash_whitelist.yaml: non-whitelist proxy")
        require(names, f"clash_{mode}.yaml: no supported proxies")
        groups = cfg["proxy-groups"]
        known = names | {g["name"] for g in groups} | {"DIRECT", "REJECT"}
        for group in groups:
            require(group.get("proxies") and all(p in known for p in group["proxies"]),
                    f"clash_{mode}.yaml: invalid group references")
        if mode == "whitelist":
            default = next(g for g in groups if g["name"] == groups[0]["proxies"][0])
            require(set(default["proxies"]) <= names,
                    "clash_whitelist.yaml: default group has no whitelist route")
    return profiles + reserve_profiles


def check_cores(folder, profiles, xray, mihomo):
    folder = Path(folder).resolve()
    with tempfile.TemporaryDirectory(prefix="subscription-validation-") as tmp:
        for index, profile in enumerate(profiles, 1):
            result = subprocess.run([str(Path(xray).resolve()), "run", "-test", "-config", "stdin:"],
                                    input=json.dumps(profile, ensure_ascii=False), capture_output=True,
                                    text=True, encoding="utf-8", errors="replace", timeout=30)
            require(result.returncode == 0,
                    f"Xray profile {index}: {(result.stdout + result.stderr)[-1500:]}")
        for mode in ("regular", "whitelist"):
            result = subprocess.run([str(Path(mihomo).resolve()), "-t", "-d", tmp,
                                     "-f", str(folder / f"clash_{mode}.yaml")],
                                    capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
            require(result.returncode == 0,
                    f"Mihomo {mode}: {(result.stdout + result.stderr)[-1500:]}")
    print(f"Core validation OK: {len(profiles)} Xray profiles, 2 Mihomo configs")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder")
    parser.add_argument("--previous")
    parser.add_argument("--require-probe", action="store_true")
    parser.add_argument("--xray")
    parser.add_argument("--mihomo")
    args = parser.parse_args()
    if bool(args.xray) != bool(args.mihomo):
        parser.error("--xray and --mihomo must be supplied together")
    try:
        profiles = validate_output(args.folder, args.previous, args.require_probe)
        if args.xray:
            check_cores(args.folder, profiles, args.xray, args.mihomo)
        else:
            print("Structural validation OK (core checks not requested)")
    except (ValueError, OSError, KeyError, TypeError, StopIteration, yaml.YAMLError,
            subprocess.TimeoutExpired) as exc:
        parser.exit(1, f"Publication blocked: {exc}\n")


if __name__ == "__main__":
    main()
