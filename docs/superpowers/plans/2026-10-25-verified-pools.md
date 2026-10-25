# Verified subscriptions and probe fallback

Scope: the three selected changes only. Keep current AI detection, group size,
hourly schedule and source limits.

- [x] Reproduce unverified nodes entering automatic groups and arbitrary startup
  fallback selection with failing tests.
- [x] Main TXT, Xray and Clash subscriptions contain only nodes with a successful
  probe not older than two hours. Keep unconfirmed whitelist nodes separately in
  unverified.txt and individual-only unverified.json profiles.
- [x] Probe Cloudflare trace, then Google generate_204, then Microsoft Connect
  Test through the same SOCKS inbound. Retry the sequence once on total failure;
  require each endpoint's expected status/body. Keep missing exit geography unknown.
- [x] Select each balancer fallback by minimum measured latency among its own
  verified members. Keep presentation order independent from fallback selection.
- [x] Persist health.json and validate primary/reserve separation, proof freshness,
  measured fallback choice and both core formats before copying output files.
- [x] Test with controlled responses and actual Xray cold-start routing. Run a live
  scan of the existing source snapshot, rebuild and validate generated artifacts.

Migration decision: old all.txt has no per-node health evidence and combines both
pools. For that one transition, the 50-percent retention guard compares its count
with the new primary plus reserve total. Once health.json exists, compare verified
counts only. Empty primary/whitelist/foreign groups still block publication.

Live evidence: 201 existing nodes scanned; 86 responded through their tunnels,
including 6 confirmed via Google rather than Cloudflare. 95 unconfirmed whitelist
nodes retained for manual use; 20 unsuccessful regular-only nodes dropped. Core
validation: 90 primary plus 95 manual Xray profiles and both Mihomo configs passed.
The Windows Schannel curl attempt failed locally and was discarded. A separate
official curl build using existing trusted roots performed the successful scan;
TLS certificate verification remained enabled. No Happ/mobile-network test or
GitHub publication was performed.

Final verification: 27 unittest cases passed with both real core paths supplied,
including UDP cold-start routing. Validation of the final copied files accepted
all 185 Xray profiles and both Mihomo exports. Self-review completed.
