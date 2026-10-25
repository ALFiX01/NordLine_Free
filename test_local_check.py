import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from test_subscriptions import node, write_probe


class LocalCheckTests(unittest.TestCase):
    def test_client_exclusion_removes_renamed_node_from_all_source_groups(self):
        import build
        import local_check
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, work = root / "source", root / "work"
            source.mkdir()
            work.mkdir()
            blocked, kept = node(sni="blocked.example"), node(sni="kept.example")
            renamed = blocked["raw"].split("#")[0] + "#new-name"
            for name in ("all.txt", "whitelist.txt", "unverified.txt"):
                (source / name).write_text(renamed + "\n" + kept["raw"], encoding="utf-8")
            nodes = local_check.prepare_sources(source, work, {build.probe_key(blocked)})
            self.assertEqual(set(nodes), {build.probe_key(kept)})
            for name in ("white-source.txt", "black-source.txt", "combined.txt"):
                keys = {build.probe_key(n) for line in (work / name).read_text(encoding="utf-8").splitlines()
                        if (n := build.parse_link(line))}
                self.assertNotIn(build.probe_key(blocked), keys)
            self.assertIn(build.probe_key(kept), {build.probe_key(build.parse_link(line)) for line in
                          (work / "combined.txt").read_text(encoding="utf-8").splitlines()})

    def test_failed_local_scan_preserves_previous_subscription(self):
        import build
        import local_check
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "core").touch()
            source = root / "source"
            source.mkdir()
            blocked, kept = node(sni="blocked.example"), node(sni="kept.example")
            for name in ("all.txt", "whitelist.txt", "unverified.txt"):
                (source / name).write_text(blocked["raw"] + "\n" + kept["raw"] if name != "unverified.txt" else "", encoding="utf-8")
            current = root / "local/current"
            current.mkdir(parents=True)
            (current / "auto.json").write_text("previous subscription", encoding="utf-8")
            (current.parent / "client-exclusions.json").write_text(json.dumps([build.probe_key(blocked)]))
            args = SimpleNamespace(xray=str(root / "core"), mihomo=str(root / "core"),
                                   folder=str(root / "local"), source_dir=str(source), curl=None, workers=8)
            def failed_scan(command, **kwargs):
                candidates = Path(command[8]).read_text(encoding="utf-8")
                self.assertNotIn(blocked["raw"], candidates)
                self.assertIn(kept["raw"], candidates)
                Path(command[7]).write_text(json.dumps({"__meta__": {"checked_at": datetime.now(timezone.utc).isoformat()}}))
            with patch("local_check.subprocess.run", side_effect=failed_scan):
                with self.assertRaisesRegex(ValueError, "No nodes passed"):
                    local_check.check(args)
            self.assertEqual((current / "auto.json").read_text(encoding="utf-8"), "previous subscription")

    def test_intersection_keeps_only_nodes_with_two_successful_passes(self):
        import local_check
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "probe.json"
            a, b, c = node(sni="a.example"), node(sni="b.example"), node(sni="c.example")
            write_probe(path, [a, b])
            first = json.loads(path.read_text())
            write_probe(path, [a, c])
            second = json.loads(path.read_text())
            merged = local_check.intersect_reports(first, second)
            import build
            self.assertTrue(merged[build.probe_key(a)]["ok"])
            self.assertFalse(merged[build.probe_key(b)]["ok"])
            self.assertNotIn(build.probe_key(c), merged)
            self.assertEqual(merged["__meta__"]["scope"], "local-network")
            self.assertEqual(merged["__meta__"]["passes"], 2)

    def test_stale_first_pass_cannot_certify_local_nodes(self):
        import local_check
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "probe.json"
            write_probe(path, [node()])
            first = json.loads(path.read_text())
            second = json.loads(path.read_text())
            first["__meta__"]["checked_at"] = "2000-01-01T00:00:00+00:00"
            with self.assertRaisesRegex(ValueError, "stale"):
                local_check.intersect_reports(first, second)

    def test_local_http_serves_only_verified_files_and_supplies_title(self):
        import local_check
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            body = b'[{"remarks":"test"}]'
            (root / "auto.json").write_bytes(body)
            (root / "private.txt").write_text("private")
            (root / "stats.json").write_text(json.dumps({"last_successful_probe_at": datetime.now(timezone.utc).isoformat()}))
            (root / "local-proof.json").write_text(json.dumps({"scope": "local-network", "passes": 2}))
            server = local_check.make_server(root, "127.0.0.1", 0)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                url = f"http://127.0.0.1:{server.server_port}"
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                with opener.open(url + "/auto.json", timeout=3) as response:
                    self.assertEqual(response.read(), body)
                    self.assertEqual(response.headers["profile-title"], "NordLine_Free WiFi")
                    self.assertEqual(response.headers["ping-type"], "proxy-head")
                    self.assertEqual(response.headers["check-url-via-proxy"], "https://www.gstatic.com/generate_204")
                    self.assertIn("no-store", response.headers["Cache-Control"])
                for path in ("/private.txt", "/unverified.json", "/../README.md", "/"):
                    with self.subTest(path=path), self.assertRaises(urllib.error.HTTPError) as error:
                        opener.open(url + path, timeout=3)
                    self.assertEqual(error.exception.code, 404)
                (root / "stats.json").write_text(json.dumps({"last_successful_probe_at": "2000-01-01T00:00:00+00:00"}))
                with self.assertRaises(urllib.error.HTTPError) as stale:
                    opener.open(url + "/auto.json", timeout=3)
                self.assertEqual(stale.exception.code, 503)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
