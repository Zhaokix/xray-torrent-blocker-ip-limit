# Local Daemon Hardening Status

This file tracks the production-safe hardening work for the current local daemon scope.
It does not change the long-term target described in `docs/AGENTS.md`.

## Scope

- Keep the project as a local Xray IP-limit daemon.
- Do not expand into distributed enforcement in this phase.
- Do not modify `docs/AGENTS.md` in this phase.

## Phases

### Phase 1: Runtime Safety and Consistency

Status: completed

- [x] Make config loading fail fast.
- [x] Add explicit config validation for critical fields.
- [x] Fix ban flow consistency between storage and firewall actions.
- [x] Fix unban flow consistency between storage and firewall actions.
- [x] Add safer webhook delivery behavior.

### Phase 2: Enforcement Layer Cleanup

Status: completed

- [x] Introduce a dedicated firewall abstraction.
- [x] Split iptables and nftables backends.
- [x] Move iptables rules into a dedicated chain.
- [x] Add firewall state reconciliation on startup.

### Phase 3: Parsing and Detection Hardening

Status: completed

- [x] Remove unnecessary `unsafe` parsing helpers.
- [x] Support robust IP parsing and validation.
- [x] Document and test the exact active-IP counting semantics.
- [x] Improve log parsing resilience.

### Phase 4: Test Coverage

Status: completed

- [x] Add config unit tests.
- [x] Add storage unit tests.
- [x] Add parser unit tests.
- [x] Add watcher state-transition tests.

### Phase 5: Operational Cleanup

Status: completed

- [x] Clean up broken comment encoding and non-English comments in touched files.
- [x] Align README and local-daemon behavior where needed.
- [x] Review service and install artifacts for the hardened runtime behavior.

## Notes

- Update this file as each phase progresses.
- Keep changes incremental and production-safe after every patch.
- Verified with `go test ./...` and `go build ./...` on Windows after Phase 1 changes.
- Verified with `go test ./...` and `go build ./...` on Windows after Phase 2 changes.
- Verified with `go test ./...` and `go build ./...` on Windows after Phase 3 changes.
- Verified with `go test ./...` and `go build ./...` on Windows after Phase 5 changes.
