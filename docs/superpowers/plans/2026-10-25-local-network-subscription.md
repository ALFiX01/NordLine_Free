# Local-network subscription

User confirmed this Windows computer shares the Wi-Fi network where Happ nodes
show NA. A direct curl control returned Cloudflare loc=RU, warp=off, gateway=off.
No explicit HTTP/HTTPS/ALL proxy environment variables were set. The desktop's
reported LAN address is 192.168.1.126. This is computer-network evidence, not an
actual phone/Happ test.

Implementation:
- [x] Add failing tests for intersecting two probe reports, stale reports and
  serving only whitelisted primary files with subscription metadata.
- [x] Add probe worker control (default CI 48, local 8), second-pass Gemini skip
  and bounded progress reporting. Both passes use the existing strict HTTPS HEAD
  plus independent-target policy and the same Xray-generated outbounds.
- [x] Add local_check.py. Fetch one immutable GitHub revision; preserve whitelist
  membership using canonical identities and the whitelist/reserve source files.
  Check all candidates, then recheck first-pass successes. Only the intersection
  reaches validated staging output. Do not modify root/public subscription files.
- [x] Serve primary files only, with profile-title, proxy-head and the matching
  check URL. Reject stale local outputs. No directory listing or reserve endpoint.
- [x] Complete the ongoing two-pass network check and validate all generated
  profiles with both real cores. Publish under ignored .local-subscription/current.
- [x] Run the full suite and start a LAN HTTP endpoint; test the endpoint from
  this computer and give its URL to the user for Happ.

Completed check exec session: 31184. Command: local_check.py check with binaries
under .tmp/tools, 8 workers, PYTHONPATH=.tmp/deps and CURL_CA_BUNDLE pointing to
the existing exported trusted roots in .tmp/tools/curl/trust.pem. The first pass
started with 364 nodes. Do not restart or duplicate it. Run diagnostics and reports
are kept under .local-subscription/check-*; local results are ignored by Git.

Completed: first pass 130/364, second pass 119/130. Final primary subscription has
119 nodes, 27 AI, 57 foreign and 62 Russian. Unconfirmed nodes are not served.
Core checks passed for all 311 primary/reserve Xray profiles and both Mihomo
exports before publishing the local primary files. All four final automatic JSON
profiles returned HTTPS HEAD 204 immediately on cold start (238/234/227/258 ms).

LAN server exec session 30246 remains running on 0.0.0.0:8765. URL:
http://192.168.1.126:8765/auto.json . A direct request from this computer returned
HTTP 200, 123 JSON profiles (4 automatic plus 119 individual), correct title and
proxy-head/check URL metadata. Reserve, health, README and directory URLs return
404. The user has been asked to import/test the link; their phone result is pending.

Limit: a successful two-pass test does not guarantee future availability or a
phone's identical route. The HTTP server refuses results older than two hours;
repeat the local check to refresh them. No scheduled OS task, firewall change,
GitHub publication or automatic startup has been authorized or installed.
