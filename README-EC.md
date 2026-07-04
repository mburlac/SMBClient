# EC fork notes (README-EC.md)

Fork of kishikawakatsumi/SMBClient for EmpiricCommander (v2-49).

- Forked 2026-07-04 at upstream 66eafaa6d17e (upstream last push 2026-04-27).
- License: MIT (upstream LICENSE retained).
- Why a fork: upstream bus factor is 1 and release cadence is slow;
  EC pins an exact revision and owns the dependency (same playbook as
  mburlac/static-libgit2). Chosen over AMSMB2/libsmb2, which is
  LGPL-2.1 and was refused for the iOS binary - see EC's
  backlog/v2-48-smb-connector-spike.md for the full license analysis.

## Vetting notes (2026-07-04, adoption review)

- Zero external dependencies (Package.swift: no deps). Pure Swift.
- Auth path reviewed (Sources/SMBClient/Auth/): NTLMv2 with
  self-contained MD4 (RFC 1320) + CommonCrypto HMAC-MD5/RC4; no
  custom TLS, no key storage, no telemetry, no network egress other
  than the SMB connection itself.
- Signing: SMB2 HMAC-SHA256 (Session.swift). No SMB3 signing or
  encryption yet - planned EC-side addition.
- Dialects negotiated: SMB 2.0.2 / 2.1 only. No SMB1 anywhere.
- Transport: Network.framework NWConnection, port from caller.
- Concurrency: swift-tools 5.9, classes are not Sendable; EC wraps
  access in an actor and adds @unchecked @retroactive Sendable in its
  own layer only.

## Policy

- EC's project.yml pins an exact revision. Bumps require re-running
  the package vetting checklist (EC memory feedback_package_vetting).
- Keep the diff vs upstream minimal so upstream merges stay cheap.
