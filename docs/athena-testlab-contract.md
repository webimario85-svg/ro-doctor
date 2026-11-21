# Athena TestLab ↔ RO Doctor: offline evidence contract (M4)

This contract is implemented by RO Doctor and proposed for any future Athena TestLab runner. It does not claim that an Athena TestLab executable or repository already exists. The tools stay independent: RO Doctor imports local JSON and verifies bytes; the external runner is responsible for producing a real test result.

## Bundle layout (example only)

    output/
      run-2026-11-21.case.json
      run-2026-11-21.log

No proprietary game assets, private binaries, passwords, session tokens or private records belong in shared bundles. The files live outside the scanned game tree. Sanitize logs before calculating their digest.

## Case schema

RO Doctor validates [test-case schema v1](test-case.schema.json). Each case JSON includes:
- case_id: unique stable case identifier such as isolated-login-001
- scenario: typed identifier such as login-handshake, packet-handshake or npc-warp
- runner: producing tool/version, e.g. athena-testlab/0.1
- client_sha256: SHA-256 of the actual client executable
- server_build_sha256: SHA-256 of the deployed server executable, not a source Git hash
- status: externally reported pass, fail or unverified
- observed_at: ISO date of the reported test
- log_sha256: SHA-256 of sanitized log bytes. Required for pass/fail, nullable for unverified
- source_url: HTTPS reference recorded as text, never fetched

A runner must not fabricate positive outcomes or guess digests. Logs should record enough non-sensitive events to reproduce findings but avoid credentials, addresses and user data.

## Inspect a case and verify a log locally

Windows:

    rodoctor --client "D:\Ragnarok" --case-file "D:\reports\run.case.json" --case-log "D:\reports\run.log" --server-build-sha256 ACTUAL_64_HEX_SHA --only-check case-evidence --format json

Linux:

    rodoctor --client /opt/ragnarok --case-file /tmp/reports/run.case.json --case-log /tmp/reports/run.log --server-build-sha256 ACTUAL_64_HEX_SHA --only-check case-evidence --format json

RO Doctor first checks schema and exact client/server hash pairs. If case-log is explicitly supplied, the tool streams at most 128 MiB and compares SHA-256 to the case. A mismatch, unreadable/truncated log or missing declared checksum blocks the reported pass/fail output. A matching log yields CASE_LOG_SHA256_MATCH alongside CASE_REPORTED_PASS, CASE_REPORTED_FAIL or CASE_UNVERIFIED. Such statuses remain reports from an external source, never a verified protocol result.

Legacy case JSON without case-log remains supported: it reports the unverified source/log situation as before. The log path must be outside selected client and server roots, and the tool does not modify either root.

## Trust boundaries

Hash matching proves only that local bytes match the digest in a JSON report. It does not prove the author, runtime execution, server configuration or real client/server handshake. Source URLs are never opened. Use --fail-on warning when a bad log should block a local preflight.

Any independent runner emitting exactly this schema and an optional matching, sanitized log can integrate. No dependency on another repository or executable is required. Unknown JSON keys are rejected to prevent silent schema drift.

All RO Doctor fixtures are synthetic and are not represented as real successful game logins.
