# Subscription repair implementation plan

Goal: fix the three selected review findings and the Happ startup failure.

Scope: build.py, probe.py, validate.py, test_subscriptions.py, workflow,
README and generated configurations. Keep AI detection and probe isolation unchanged.

- [x] Add failing regressions for whitelist routing, connection identity,
  Happ DNS and cold-start balancer fallback.
- [x] Fix the generator using the existing Python implementation. Whitelist
  Clash exports contain only whitelist nodes, including AI groups. Fingerprints
  include all query parameters, normalize type/security and JSON key order in extra.
- [x] Add publication validation: nonempty output, matching counts and files,
  at least 50% of the previous all.txt count, explicit Happ DNS, eligible balancer
  fallback, Xray test of every profile, Mihomo test of both YAML files.
- [x] Record generation time and successful live probe time separately. Validate
  the staging output before copying it into the published files.
- [x] Run the complete unittest suite and real core configuration checks;
  refresh existing generated configurations without inventing live probe results.

Decisions: use a DoH DNS with an explicit hosts mapping for Happ, and fallback
to an existing member of each balancer. Both are needed: missing DNS and empty
balancer selection are different boundaries. No direct-connection fallback.

Verification must distinguish configuration validity, cold-start routing through
a controlled local server, and real mobile/Happ availability.

Evidence: 17 unittest cases pass with both core paths supplied. Xray 26.10.21
accepts all 205 existing profiles; Mihomo 1.19.33 accepts both YAML exports.
The local UDP test covers the general and AI balancers with unavailable ping
destinations. Removing fallbackTag in memory reproduces the user's empty-tag
log; restoring the generated configuration removes it. Public VLESS connections
and Happ itself were not exercised. Existing 201 node links were preserved;
last_successful_probe_at is null because the old snapshot has no check timestamp.
Final review: self-review; no agents, commits, push or live publication.
