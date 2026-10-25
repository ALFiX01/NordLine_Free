import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode
from unittest.mock import patch

import build


ROOT = Path(__file__).resolve().parent
UUID = "11111111-1111-4111-8111-111111111111"


def node(name="test", wl=True, ai=False, **params):
    query = {"security": "tls", "type": "tcp", **params}
    n = build.parse_link(f"vless://{UUID}@example.com:443?{urlencode(query)}#%F0%9F%87%A9%F0%9F%87%AA")
    n.update(name=name, wl=wl, ai=ai, verified=True, ms=100)
    return n


def write_probe(path, nodes, checked=None):
    report = {build.probe_key(n): {"ok": True, "ms": n.get("ms", 100),
                                  "exit": n["cc"], "gemini": n.get("ai", False),
                                  "policy": "https-head-plus-independent-v1",
                                  "checks": [{"url": "https://www.gstatic.com/generate_204", "method": "HEAD",
                                              "ok": True, "ms": n.get("ms", 100)},
                                             {"url": "https://www.cloudflare.com/cdn-cgi/trace", "method": "GET",
                                              "ok": True, "ms": 150}]} for n in nodes}
    report["__meta__"] = {"checked_at": checked or datetime.now(timezone.utc).isoformat()}
    path.write_text(json.dumps(report), encoding="utf-8")


class GeneratorTests(unittest.TestCase):
    def test_auto_exports_exclude_unverified_nodes(self):
        good, bad = node("good"), node("bad", ai=True)
        bad.update(verified=False, ms=1)
        profiles = build.build_xray_sub([bad, good])
        self.assertNotIn('"remarks": "bad"', json.dumps(profiles))
        self.assertTrue(all(len(c["outbounds"]) == 3 for c in profiles))
        cfg, count = build.build_clash("regular", [bad, good])
        self.assertEqual(count, 1)
        self.assertEqual(cfg["proxies"][0]["name"], "good")

    def test_fallback_uses_lowest_measured_latency_inside_each_group(self):
        nodes = [node("slow"), node("fast"), node("slow-ai", ai=True), node("fast-ai", ai=True)]
        for n, ms in zip(nodes, [900, 50, 800, 100]):
            n["ms"] = ms
        cfg = build.xray_config("auto", nodes, ai_routing=True)
        self.assertEqual(cfg["routing"]["balancers"][0]["fallbackTag"], "node-ru-2")
        self.assertEqual(cfg["routing"]["balancers"][1]["fallbackTag"], "node-ai-4")

    def test_whitelist_export_excludes_regular_only_nodes_from_every_group(self):
        nodes = [node("wl"), node("wl-ai", ai=True), node("regular-ai", wl=False, ai=True)]
        cfg, count = build.build_clash("whitelist", nodes)
        self.assertEqual(count, 2)
        self.assertEqual({p["name"] for p in cfg["proxies"]}, {"wl", "wl-ai"})
        groups = {g["name"]: g for g in cfg["proxy-groups"]}
        default = groups[cfg["proxy-groups"][0]["proxies"][0]]
        self.assertEqual(set(default["proxies"]), {"wl", "wl-ai"})
        for rule in cfg["rules"]:
            if rule.startswith("DOMAIN-SUFFIX,chatgpt.com,"):
                self.assertEqual(groups[rule.split(",")[-1]]["proxies"], ["wl-ai"])
        self.assertNotIn("regular-ai", json.dumps(cfg))

    def test_regular_export_keeps_regular_only_nodes(self):
        cfg, count = build.build_clash("regular", [node("wl"), node("regular", wl=False)])
        self.assertEqual(count, 2)
        self.assertEqual({p["name"] for p in cfg["proxies"]}, {"wl", "regular"})

    def test_connection_settings_do_not_share_probe_or_dedup_identity(self):
        base = node()
        for key, value in {"flow": "xtls-rprx-vision", "fp": "firefox", "alpn": "h2",
                           "spx": "/test", "extra": '{"downloadSettings":{"address":"other.example"}}',
                           "future-option": "value", "sni": "other.example"}.items():
            with self.subTest(key=key):
                changed = node(**{key: value})
                self.assertNotEqual(build.dedup_key(base), build.dedup_key(changed))
                self.assertNotEqual(build.probe_key(base), build.probe_key(changed))

    def test_equivalent_links_deduplicate_despite_label_and_json_order(self):
        a = node(type="raw", extra='{"a":1,"b":2}')
        b = node(type="tcp", extra='{"b":2, "a":1}')
        b["frag"] = "another label"
        b["q"] = dict(reversed(list(b["q"].items())))
        self.assertEqual(build.dedup_key(a), build.dedup_key(b))
        self.assertEqual(build.probe_key(a), build.probe_key(b))

    def test_every_xray_profile_has_happ_dns_and_eligible_startup_fallback(self):
        profiles = build.build_xray_sub([node("wl"), node("ai", ai=True)])
        for cfg in profiles:
            with self.subTest(profile=cfg["remarks"]):
                dns = cfg.get("dns", {})
                self.assertTrue(dns.get("servers"), "Happ needs dns.servers")
                self.assertEqual(dns["hosts"]["cloudflare-dns.com"], "1.1.1.1")
                outbounds = {o["tag"] for o in cfg["outbounds"] if o["protocol"] == "vless"}
                for bal in cfg["routing"]["balancers"]:
                    fallback = bal.get("fallbackTag")
                    self.assertIn(fallback, outbounds)
                    self.assertTrue(any(fallback.startswith(s) for s in bal["selector"]))

    def test_cold_start_fallback_stays_inside_each_balancer(self):
        cfg = build.xray_config("auto", [node("regular"), node("ai", ai=True)], ai_routing=True)
        for bal in cfg["routing"]["balancers"]:
            fallback = bal.get("fallbackTag", "")
            self.assertTrue(fallback, "No route before first observatory result")
            self.assertTrue(any(fallback.startswith(s) for s in bal["selector"]))

    def test_build_preserves_distinct_connections_and_merges_whitelist_membership(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            a, b = node(), node(flow="xtls-rprx-vision")
            (root / "black").write_text(a["raw"] + "\n" + b["raw"] + "\n", encoding="utf-8")
            (root / "white").write_text(a["raw"] + "\n", encoding="utf-8")
            write_probe(root / "probe.json", [a, b])
            result = subprocess.run([sys.executable, "-X", "utf8", str(ROOT / "build.py"),
                                     f"{root / 'black'}=bl,{root / 'white'}", str(root / "out"),
                                     "--alive", str(root / "probe.json")],
                                    capture_output=True, text=True, encoding="utf-8")
            self.assertEqual(result.returncode, 0, result.stderr)
            stats = json.loads((root / "out/stats.json").read_text(encoding="utf-8"))
            self.assertEqual(stats["после дедупа"], 2)
            white = (root / "out/whitelist.txt").read_text(encoding="utf-8")
            self.assertEqual(sum(l.startswith("vless://") for l in white.splitlines()), 1)


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.out = self.root / "out"
        self.previous = self.root / "previous"
        self.previous.mkdir()
        self.source = self.root / "source"
        self.source.write_text(node()["raw"] + "\n", encoding="utf-8")
        self.report = self.root / "probe.json"
        write_probe(self.report, [node()])
        result = subprocess.run([sys.executable, "-X", "utf8", str(ROOT / "build.py"),
                                 str(self.source), str(self.out), "--alive", str(self.report)], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def validate(self, succeeds, *args):
        result = subprocess.run([sys.executable, "-X", "utf8", str(ROOT / "validate.py"),
                                 str(self.out), *args], capture_output=True, text=True, encoding="utf-8")
        if succeeds:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0)
        return result.stdout + result.stderr

    def edit_json(self, filename, edit):
        path = self.out / filename
        data = json.loads(path.read_text(encoding="utf-8"))
        edit(data)
        path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")

    def test_accepts_consistent_output_with_fixture_probe(self):
        self.validate(True)
        stats = json.loads((self.out / "stats.json").read_text(encoding="utf-8"))
        self.assertIsNotNone(stats["last_successful_probe_at"])
        self.assertIsNotNone(datetime.fromisoformat(stats["generated_at"]).tzinfo)

    def test_rejects_empty_or_inconsistent_output(self):
        (self.out / "all.txt").write_text("# empty\n", encoding="utf-8")
        self.assertIn("all.txt", self.validate(False))

    def test_rejects_large_drop_and_keeps_previous_files(self):
        old = (node()["raw"] + "\n") * 10
        (self.previous / "all.txt").write_text(old, encoding="utf-8")
        self.assertIn("50%", self.validate(False, "--previous", str(self.previous)))
        self.assertEqual((self.previous / "all.txt").read_text(encoding="utf-8"), old)

    def test_rejects_missing_dns(self):
        self.edit_json("auto.json", lambda items: items[0].pop("dns"))
        self.assertIn("DNS", self.validate(False))

    def test_rejects_missing_or_ineligible_fallback(self):
        self.edit_json("auto.json", lambda items: items[0]["routing"]["balancers"][0].update(fallbackTag="direct"))
        self.assertIn("fallback", self.validate(False))

    def test_rejects_whitelist_routes_to_regular_only_nodes(self):
        import yaml
        path = self.out / "clash_whitelist.yaml"
        cfg = yaml.safe_load(path.read_text(encoding="utf-8"))
        cfg["proxies"].append(build.clash_proxy(node("regular-only", wl=False)))
        path.write_text(yaml.safe_dump(cfg, allow_unicode=True), encoding="utf-8")
        self.assertIn("whitelist", self.validate(False))

    def test_requires_a_recent_successful_probe_in_workflow(self):
        self.edit_json("stats.json", lambda stats: stats.update(last_successful_probe_at=None))
        self.assertIn("probe", self.validate(False, "--require-probe"))
        self.edit_json("stats.json", lambda stats: stats.update(last_successful_probe_at="2000-01-01T00:00:00+00:00"))
        self.assertIn("probe", self.validate(False, "--require-probe"))

    def test_build_consumes_new_probe_identity_and_records_check_time(self):
        checked = datetime.now(timezone.utc).isoformat()
        report = self.root / "probe.json"
        fixture = node(ai=True)
        fixture["ms"] = 123
        write_probe(report, [fixture], checked)
        result = subprocess.run([sys.executable, "-X", "utf8", str(ROOT / "build.py"),
                                 str(self.source), str(self.out), "--alive", str(report)], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        stats = json.loads((self.out / "stats.json").read_text(encoding="utf-8"))
        self.assertEqual(stats["ИИ"], 1)
        self.assertEqual(stats["last_successful_probe_at"], checked)
        self.validate(True, "--require-probe")

    def test_failed_whitelist_node_is_preserved_only_in_manual_reserve(self):
        bad = node("bad", sni="failed.example")
        self.source.write_text(node()["raw"] + "\n" + bad["raw"] + "\n", encoding="utf-8")
        result = subprocess.run([sys.executable, "-X", "utf8", str(ROOT / "build.py"), str(self.source),
                                 str(self.out), "--alive", str(self.report)], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        reserve = (self.out / "unverified.txt").read_text(encoding="utf-8")
        self.assertIn("failed.example", reserve)
        self.assertNotIn("failed.example", (self.out / "all.txt").read_text(encoding="utf-8"))
        for cfg in json.loads((self.out / "unverified.json").read_text(encoding="utf-8")):
            self.assertFalse(cfg["routing"]["balancers"])
            self.assertNotIn("burstObservatory", cfg)
        self.validate(True)

    def test_publication_rejects_unverified_health_in_primary(self):
        self.edit_json("health.json", lambda health: health[build.probe_key(node())].update(status="unverified"))
        self.assertIn("health", self.validate(False))

    def test_publication_rejects_slow_fallback_when_faster_verified_node_exists(self):
        fast = node(sni="fast.example")
        fast["ms"] = 10
        self.source.write_text(node()["raw"] + "\n" + fast["raw"] + "\n", encoding="utf-8")
        write_probe(self.report, [node(), fast])
        result = subprocess.run([sys.executable, "-X", "utf8", str(ROOT / "build.py"), str(self.source),
                                 str(self.out), "--alive", str(self.report)], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.edit_json("auto.json", lambda items: items[0]["routing"]["balancers"][0].update(fallbackTag="node-ru-2"))
        self.assertIn("fallback", self.validate(False))

    def test_stale_or_missing_probe_does_not_create_verified_auto_groups(self):
        for checked in (None, "2000-01-01T00:00:00+00:00"):
            args = [sys.executable, "-X", "utf8", str(ROOT / "build.py"), str(self.source), str(self.out)]
            if checked:
                write_probe(self.report, [node()], checked)
                args += ["--alive", str(self.report)]
            result = subprocess.run(args, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads((self.out / "auto.json").read_text(encoding="utf-8")), [])
            self.assertIn("vless://", (self.out / "unverified.txt").read_text(encoding="utf-8"))

    def test_stricter_policy_migration_counts_nodes_moved_to_reserve(self):
        nodes = [node(sni=f"old-{i}.example") for i in range(8)]
        self.source.write_text(node()["raw"] + "\n" + "\n".join(n["raw"] for n in nodes), encoding="utf-8")
        old = [node(), *nodes]
        (self.previous / "all.txt").write_text("\n".join(n["raw"] for n in old), encoding="utf-8")
        (self.previous / "health.json").write_text(json.dumps({build.probe_key(n): {"ok": True, "status": "verified"}
                                                               for n in old}), encoding="utf-8")
        result = subprocess.run([sys.executable, "-X", "utf8", str(ROOT / "build.py"), str(self.source),
                                 str(self.out), "--alive", str(self.report)], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.validate(True, "--previous", str(self.previous))
        (self.previous / "health.json").write_text(json.dumps({build.probe_key(n): {"policy": "https-head-plus-independent-v1"}
                                                               for n in old}), encoding="utf-8")
        self.assertIn("50%", self.validate(False, "--previous", str(self.previous)))

    def test_client_probe_destination_must_match_checked_endpoint(self):
        self.edit_json("auto.json", lambda items: items[0]["burstObservatory"]["pingConfig"].update(
            destination="http://www.gstatic.com/generate_204"))
        self.assertIn("client probe differs", self.validate(False))

    def test_old_one_endpoint_report_cannot_restore_verified_status(self):
        report = json.loads(self.report.read_text(encoding="utf-8"))
        for value in report.values():
            value.pop("policy", None)
            value.pop("checks", None)
        self.report.write_text(json.dumps(report), encoding="utf-8")
        result = subprocess.run([sys.executable, "-X", "utf8", str(ROOT / "build.py"), str(self.source),
                                 str(self.out), "--alive", str(self.report)], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads((self.out / "auto.json").read_text(encoding="utf-8")), [])


    @unittest.skipUnless(os.environ.get("XRAY_BIN") and os.environ.get("MIHOMO_BIN"), "Set core binary paths")
    def test_core_gate_rejects_invalid_xray_inbound(self):
        self.edit_json("auto.json", lambda items: items[0]["inbounds"][0].update(protocol="invalid"))
        message = self.validate(False, "--xray", os.environ["XRAY_BIN"],
                                "--mihomo", os.environ["MIHOMO_BIN"])
        self.assertIn("Xray profile 1", message)


class ProbeTests(unittest.TestCase):
    def test_cloudflare_only_does_not_make_node_verified(self):
        import probe
        def response(command, **kwargs):
            if 'https://www.cloudflare.com/cdn-cgi/trace' in command:
                return subprocess.CompletedProcess([], 0, 'loc=TH\n\n200 0.1')
            return subprocess.CompletedProcess([], 28, '')
        with patch('probe.subprocess.run', side_effect=response):
            self.assertFalse(probe.check_connectivity(31001)['ok'])

    def test_client_probe_must_pass_even_if_other_two_targets_work(self):
        import probe
        def response(command, **kwargs):
            if 'https://www.gstatic.com/generate_204' in command:
                return subprocess.CompletedProcess([], 28, '')
            body = 'loc=DE\n' if 'https://www.cloudflare.com/cdn-cgi/trace' in command else 'Microsoft Connect Test'
            return subprocess.CompletedProcess([], 0, body+'\n200 0.1')
        with patch('probe.subprocess.run', side_effect=response):
            self.assertFalse(probe.check_connectivity(31001)['ok'])

    def test_cloudflare_failure_uses_third_target_with_client_probe(self):
        import probe
        failure = subprocess.CompletedProcess([], 0, "bad\n503 0.1")
        success = subprocess.CompletedProcess([], 0, "\n204 0.25")
        secondary = subprocess.CompletedProcess([], 0, "Microsoft Connect Test\n200 0.3")
        with patch("probe.subprocess.run", side_effect=[success, failure, secondary]) as request:
            result = probe.check_connectivity(31001)
        self.assertTrue(result["ok"])
        self.assertEqual(result["ms"], 250)
        self.assertIsNone(result["exit"])
        self.assertIn("-I", request.call_args_list[0].args[0])
        for call in request.call_args_list:
            self.assertIn("127.0.0.1:31001", call.args[0])
            self.assertIn("--socks5-hostname", call.args[0])

    def test_all_target_failures_remain_unverified(self):
        import probe
        with patch("probe.subprocess.run", return_value=subprocess.CompletedProcess([], 28, "")):
            self.assertFalse(probe.check_connectivity(31001)["ok"])

    def test_client_head_and_cloudflare_confirm_same_tunnel(self):
        import probe
        first = subprocess.CompletedProcess([], 0, "HTTP/2 204\r\n\r\n\n204 0.15")
        success = subprocess.CompletedProcess([], 0, "loc=DE\n\n200 0.3")
        with patch("probe.subprocess.run", side_effect=[first, success]):
            result = probe.check_connectivity(31001)
        self.assertTrue(result["ok"])
        self.assertEqual(result["ms"], 150)
        self.assertEqual(result["exit"], "DE")
        self.assertEqual(len(result["checks"]), 2)

    def test_arbitrary_success_page_does_not_confirm_tunnel(self):
        import probe
        portal = subprocess.CompletedProcess([], 0, "<html>Login</html>\n200 0.1")
        with patch("probe.subprocess.run", return_value=portal):
            result = probe.check_connectivity(31001)
        self.assertFalse(result["ok"])
        self.assertEqual(len(result["failed_targets"]), 2)


@unittest.skipUnless(os.environ.get("XRAY_BIN"), "Set XRAY_BIN for the real-core startup check")
class CoreStartupTests(unittest.TestCase):
    def test_udp_routes_before_first_successful_ping(self):
        # Local freedom outbounds isolate routing from public VLESS availability.
        # The configuration and balancers come from the production generator.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as port_socket:
            port_socket.bind(("127.0.0.1", 0))
            socks_port = port_socket.getsockname()[1]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as echo:
            echo.bind(("127.0.0.1", 0))
            echo.settimeout(10)
            echo_port = echo.getsockname()[1]

            def reply():
                for _ in range(2):
                    try:
                        data, address = echo.recvfrom(4096)
                        echo.sendto(data, address)
                    except OSError:
                        return

            worker = threading.Thread(target=reply, daemon=True)
            worker.start()
            cfg = build.xray_config("startup", [node("regular"), node("ai", ai=True)], ai_routing=True)
            cfg["inbounds"] = [cfg["inbounds"][0]]
            cfg["inbounds"][0]["port"] = socks_port
            cfg["dns"]["hosts"]["chatgpt.com"] = "127.0.0.1"
            cfg["outbounds"] = [{"tag": o["tag"], "protocol": "freedom",
                                 "settings": {"domainStrategy": "UseIP"}}
                                for o in cfg["outbounds"] if o["protocol"] == "vless"]
            cfg["burstObservatory"]["pingConfig"]["destination"] = "http://127.0.0.1:1"
            proc = subprocess.Popen([os.environ["XRAY_BIN"], "run", "-config", "stdin:"],
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            try:
                proc.stdin.write(json.dumps(cfg).encode())
                proc.stdin.close()
                deadline = time.monotonic() + 5
                while True:
                    try:
                        control = socket.create_connection(("127.0.0.1", socks_port), timeout=1)
                        break
                    except OSError:
                        if proc.poll() is not None or time.monotonic() >= deadline:
                            self.fail("Xray did not open SOCKS inbound")
                        time.sleep(0.05)
                with control:
                    control.settimeout(5)
                    control.sendall(b"\x05\x01\x00")
                    self.assertEqual(control.recv(2), b"\x05\x00")
                    control.sendall(b"\x05\x03\x00\x01" + b"\x00" * 6)
                    response = control.recv(10)
                    self.assertEqual(response[:4], b"\x05\x00\x00\x01")
                    udp_port = int.from_bytes(response[8:10], "big")
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                        udp.settimeout(5)
                        for destination in (b"\x01\x7f\x00\x00\x01", b"\x03\x0bchatgpt.com"):
                            payload = b"cold-start-dns-test"
                            udp.sendto(b"\x00\x00\x00" + destination + echo_port.to_bytes(2, "big") + payload,
                                       ("127.0.0.1", udp_port))
                            reply_packet = udp.recv(4096)
                            self.assertTrue(reply_packet.endswith(payload))
            finally:
                proc.terminate()
                proc.wait(timeout=5)
                output = proc.stdout.read().decode("utf-8", errors="replace")
                proc.stdout.close()
            worker.join(timeout=1)
            self.assertNotIn("balancing strategy returns empty tag", output)


if __name__ == "__main__":
    unittest.main()
