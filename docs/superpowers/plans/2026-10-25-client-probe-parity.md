# Client probe parity repair

Observed: the published snapshot contained 336 verified nodes. A reproduced
Cloudflare-only success on Thailand #1 was accepted while the same full JSON
profile could not reach Google's client probe. Two more sampled nodes no longer
answered any probe. On the old automatic profiles, the first HTTPS requests
timed out/failed despite later HTTP requests succeeding.

Changes:
- [x] Add failing regressions for Cloudflare-only and failed client-probe cases.
- [x] Require Google's HTTPS HEAD 204 plus one independent validated GET response
  in the same attempt. Retry a failed attempt once; fail early on the mandatory
  probe instead of probing unrelated sites that cannot rescue the result.
- [x] Use the same HTTPS URL for Xray and Clash availability probes. Rank startup
  fallback by the latency measured to that URL.
- [x] Require the explicit policy and per-target evidence in build/validation.
  Reports produced by the old one-target policy cannot certify current nodes.
- [x] Preserve the retention gate for comparable policies. During migration,
  count preserved manual reserves so a weaker old result cannot block cleanup.
- [x] Recheck the latest 376 published nodes, build staged outputs and validate
  primary plus reserve profiles with Xray 26.10.21 and Mihomo 1.19.33.

Evidence: 152 nodes passed the new network probe; 151 survived the source filters
for primary output, 160 were retained for manual checking. All 315 Xray profiles
and both Mihomo exports passed core validation. Cold-start HTTPS HEAD requests
through the new general, whitelist and AI automatic profiles returned HTTP 204
in 244, 136 and 214 ms respectively in this environment.

User reports that the same node fails via both auto.json and all.txt on Wi-Fi.
This rules against blaming JSON alone, but no node name or client connection log
was supplied. No test in the user's Wi-Fi/Happ was performed. Do not claim this
repair proves their local access; do not silently publish or push these changes.

Final checks: all 36 unittest cases passed, including the real-core cold-start
regression and Git publication tests. Twelve generated artifacts were copied only
after core validation; their hashes match the validated staging files. Structural
publication validation passed again on the final workspace outputs. No push.
