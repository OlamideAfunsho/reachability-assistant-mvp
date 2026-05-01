# Autonomys Reachability Assistant MVP

Small Linux-first CLI for checking whether a Space Acres node is reachable, fixing the parts it safely can, and returning a clear diagnosis when it cannot.

Current scope:

- Linux only
- Space Acres profile only
- UFW firewall support only
- One router automation backend only
- CLI only
- Commands: `inspect`, `apply`, `renew`, `report --json`

## Layout

- `src/profile.rs`
  Defines the Space Acres profile and its required public ports: `30333/tcp` and `30433/tcp`.
- `src/inspect.rs`
  Discovery and verification:
  - listener checks
  - basic port-conflict hints
  - UFW inspection
  - LAN/default gateway/public IP discovery
  - one router backend probe via `upnpc`
  - unit-testable parsing and classification logic for the fixed MVP outcomes
- `src/apply.rs`
  Safe fix path:
  - add UFW allow rules
  - attempt one router mapping method for both required Space Acres ports
  - target the detected LAN IP instead of a hardcoded loopback address
  - re-run inspection after changes
- `src/renew.rs`
  Lightweight renewal and drift-aware re-checks:
  - re-attempt router mappings for the current LAN IP
  - compare current LAN IP and gateway against previously known values when provided
  - report drift in the final output
- `src/model.rs`
  Report shape and fixed MVP classifications.
- `src/main.rs`
  CLI entrypoint and human-readable output.

## Commands

```bash
reachability-assistant inspect --profile space-acres
reachability-assistant apply --profile space-acres
reachability-assistant renew --profile space-acres --previous-lan-ip 192.168.1.50 --previous-gateway 192.168.1.1
reachability-assistant report --profile space-acres --json
```

## MVP Classifications

The report currently uses the fixed classification set from the MVP proposal:

- `healthy`
- `missing_listener`
- `port_conflict`
- `local_firewall_block`
- `manual_router_action_required`
- `router_automation_unsupported`
- `likely_upstream_restriction`

## Notes

The project currently avoids third-party Rust crates so it can be checked offline in constrained environments.

Verification completed so far:

```bash
cargo check --offline
cargo check --tests --offline
```

Saved sample outputs for the MVP deliverables live under `docs/sample-outputs/`:

- `healthy.txt` and `healthy.json`
- `local-firewall-block.txt` and `local-firewall-block.json`
- `manual-router-action-required.txt` and `manual-router-action-required.json`
- `apply-healthy.txt` and `apply-healthy.json`
- `apply-skipped-preflight.txt` and `apply-skipped-preflight.json`
- `apply-manual-router-followup.txt` and `apply-manual-router-followup.json`
- `renew-healthy-with-drift.txt` and `renew-healthy-with-drift.json`
- `renew-manual-review.txt` and `renew-manual-review.json`

Linux validation artifacts:

- `docs/linux-validation-runbook.md`
- `docs/mvp-validation-checklist.md`
- `docs/release-checklist.md`
- `docs/packaging-notes.md`

On this Windows machine, `cargo build` cannot finish because the MSVC linker (`link.exe`) is not installed. That is an environment issue, not a Rust source issue. Since the MVP target platform is Linux, the next meaningful verification step is to run the tool on a Linux box with:

- `ss`
- `ufw`
- `ip`
- `curl`
- `miniupnpc` / `upnpc`

installed and available on `PATH`.

The repository now also includes unit tests that exercise the main MVP classifications using mocked command outputs. On this host, `cargo test` still stops at the final Windows linker step for the same `link.exe` reason, but `cargo check --tests --offline` confirms that the test code itself is valid.
