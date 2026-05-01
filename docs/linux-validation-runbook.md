# Linux Validation Runbook

This runbook is for validating the MVP on a real Linux machine.

The MVP target is intentionally narrow:

- Linux only
- Space Acres only
- UFW only
- one router backend only (`upnpc`)
- CLI only

## Goal

By the end of this validation pass, we should be able to demonstrate these three MVP outcomes:

1. a healthy case
2. a local fix case
3. a non-fixable case with exact follow-up guidance

Those map directly to the sample outputs already saved under `docs/sample-outputs/`.

## Host Requirements

The Linux host should have these commands available on `PATH`:

- `ss`
- `ufw`
- `ip`
- `curl`
- `upnpc`

You can verify that quickly with:

```bash
which ss ufw ip curl upnpc
```

For Debian or Ubuntu style environments, the usual install path is:

```bash
sudo apt update
sudo apt install -y iproute2 ufw curl miniupnpc
```

## Build And Run

On the Linux machine:

```bash
cargo check
cargo run -- inspect --profile space-acres
cargo run -- report --profile space-acres --json
```

If the system has the full Rust toolchain and linker installed correctly, you can also use:

```bash
cargo test
```

## Preflight Checks

Before validating the scenarios, confirm these baseline facts:

```bash
ss -ltnp | grep -E '30333|30433'
ufw status
ip route
hostname -I
upnpc -l
curl -fsSL https://api.ipify.org
```

What you are looking for:

- whether the Space Acres process is actually listening on `30333` and `30433`
- whether UFW is active
- whether those ports are allowed
- whether a LAN IP is present
- whether `upnpc` can reach a gateway
- whether the public IP hint looks normal or private

## Scenario 1: Healthy Case

Target result:

- classification: `healthy`

Expected shape:

- both required listeners are present
- no local conflict is detected
- UFW allows both ports
- `upnpc -l` shows entries that look like actual mappings for both ports

Suggested command sequence:

```bash
cargo run -- inspect --profile space-acres
cargo run -- report --profile space-acres --json
```

Save the output and compare it against:

- `docs/sample-outputs/healthy.txt`
- `docs/sample-outputs/healthy.json`
- `docs/sample-outputs/apply-healthy.txt`
- `docs/sample-outputs/apply-healthy.json`

## Scenario 2: Local Fix Case

Target result:

- pre-apply classification: `local_firewall_block`
- post-apply classification: ideally `healthy`, or at least a better state than before

Suggested setup:

- keep listeners running on both required ports
- remove or block one or both UFW allow rules
- leave router automation available

Suggested command sequence:

```bash
cargo run -- inspect --profile space-acres
cargo run -- apply --profile space-acres
cargo run -- report --profile space-acres --json
```

You want to verify:

- `inspect` identifies the local firewall issue before mutation
- `apply` records the UFW changes explicitly
- the post-apply report reflects the new firewall state

Use these sample files as reference:

- `docs/sample-outputs/local-firewall-block.txt`
- `docs/sample-outputs/local-firewall-block.json`

## Scenario 3: Manual Router Or Upstream Restriction Case

Target result:

- classification: `manual_router_action_required`
or
- classification: `router_automation_unsupported`
or
- classification: `likely_upstream_restriction`

Suggested setup options:

- `upnpc` cannot reach a supported gateway
- the gateway is reachable but does not actually create both mappings
- the ISP/network shape suggests CGNAT or double NAT

Suggested command sequence:

```bash
cargo run -- inspect --profile space-acres
cargo run -- apply --profile space-acres
cargo run -- report --profile space-acres --json
```

You want to verify:

- the tool does not fake success
- skipped actions are shown as skipped
- attempted but incomplete mappings are shown as attempted
- the remediation message is specific

Use these sample files as reference:

- `docs/sample-outputs/manual-router-action-required.txt`
- `docs/sample-outputs/manual-router-action-required.json`
- `docs/sample-outputs/apply-manual-router-followup.txt`
- `docs/sample-outputs/apply-manual-router-followup.json`
- `docs/sample-outputs/apply-skipped-preflight.txt`
- `docs/sample-outputs/apply-skipped-preflight.json`

## Evidence To Capture

For each scenario, capture:

- terminal output from `inspect`
- terminal output from `apply` where applicable
- JSON output from `report --json`
- the exact environment notes

Environment notes should include:

- Linux distribution
- whether UFW was active
- whether `upnpc` discovered a gateway
- whether the host was on a private LAN
- whether the case used real Space Acres services or simulated listeners

## Pass Criteria

This Linux validation pass is strong enough for the MVP if:

- the tool can produce a healthy result in one real environment
- the tool can identify and improve one local-fixable case
- the tool can refuse to fake success in one non-fixable case
- the outputs are consistent with the stored sample artifacts and fixed classification set

## Notes

The current codebase is already source-validated with:

```bash
cargo check --offline
cargo check --tests --offline
```

This runbook is about the next layer of confidence: verifying actual Linux command behavior and real network conditions.
