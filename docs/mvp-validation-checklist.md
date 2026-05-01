# MVP Validation Checklist

Use this checklist during the Linux validation pass.

## Environment

- [ ] Linux machine available
- [ ] Rust toolchain installed
- [ ] `ss` available
- [ ] `ufw` available
- [ ] `ip` available
- [ ] `curl` available
- [ ] `upnpc` available

## Build

- [ ] `cargo check` passes
- [ ] `cargo run -- inspect --profile space-acres` runs
- [ ] `cargo run -- report --profile space-acres --json` runs

## Healthy Case

- [ ] both required listeners are present
- [ ] UFW allows `30333/tcp`
- [ ] UFW allows `30433/tcp`
- [ ] `upnpc -l` shows both mappings
- [ ] tool returns `healthy`
- [ ] terminal output saved
- [ ] JSON output saved

## Local Fix Case

- [ ] listeners are present before apply
- [ ] local firewall problem reproduced
- [ ] `inspect` returns `local_firewall_block`
- [ ] `apply` records firewall actions
- [ ] post-apply state improves
- [ ] terminal output saved
- [ ] JSON output saved

## Manual Follow-Up Case

- [ ] environment reproduces router or upstream limitation
- [ ] tool does not report `healthy`
- [ ] tool returns one of:
- [ ] `manual_router_action_required`
- [ ] `router_automation_unsupported`
- [ ] `likely_upstream_restriction`
- [ ] remediation message is specific
- [ ] terminal output saved
- [ ] JSON output saved

## Deliverables

- [ ] sample outputs compared with `docs/sample-outputs/`
- [ ] short notes captured for environment and scenario setup
- [ ] demo-ready command transcript prepared
