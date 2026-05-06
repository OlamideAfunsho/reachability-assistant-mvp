# MVP Release Checklist

Use this checklist before calling the MVP ready for handoff or public release.

## Source Validation

- [ ] `cargo fmt` passes
- [ ] `cargo check --offline` passes
- [ ] `cargo check --tests --offline` passes
- [ ] CLI commands are documented:
- [ ] `inspect`
- [ ] `apply`
- [ ] `report --json`

## Sample Artifacts

- [ ] inspect healthy sample exists
- [ ] inspect local failure sample exists
- [ ] inspect manual follow-up sample exists
- [ ] apply healthy sample exists
- [ ] apply skipped preflight sample exists
- [ ] apply manual router follow-up sample exists

## Validation Docs

- [ ] Linux validation runbook exists
- [ ] MVP validation checklist exists
- [ ] release checklist exists
- [ ] packaging notes exist

## Linux Validation

- [ ] one healthy case captured on Linux
- [ ] one local-fix case captured on Linux
- [ ] one non-fixable/manual-follow-up case captured on Linux
- [ ] terminal and JSON outputs saved

## Handoff

- [ ] README reflects the current command set
- [ ] sample output paths are listed in README
- [ ] known environment limitations are documented
- [ ] next steps after MVP are written down
