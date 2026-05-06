# Packaging Notes

These notes are intentionally lightweight for the MVP. The goal is to document the minimum path for producing a usable Linux-first release, not to overdesign the packaging story.

## Current State

The codebase is prepared for:

- source-level validation
- Linux-first CLI usage
- sample-output generation
- manual validation on a Linux machine

The codebase is not yet prepared for polished cross-platform binary distribution.

## MVP Packaging Goal

For the MVP, the practical packaging goal is:

- one documented Linux build path
- one reproducible command set for running the CLI
- one release bundle that includes:
  - the binary or build instructions
  - the README
  - the Linux validation runbook
  - the sample outputs

## Suggested Linux Build Commands

On a Linux machine with Rust installed:

```bash
cargo build --release
./target/release/reachability-assistant-mvp inspect --profile space-acres
./target/release/reachability-assistant-mvp apply --profile space-acres
./target/release/reachability-assistant-mvp report --profile space-acres --json
```

## Suggested Release Bundle Contents

A minimal release folder could contain:

- `reachability-assistant-mvp` binary
- `README.md`
- `docs/linux-validation-runbook.md`
- `docs/mvp-validation-checklist.md`
- `docs/sample-outputs/`

## Known Packaging Limitations

- this repo has only been source-validated from Windows so far
- live Linux validation is still required to confirm actual `ufw` and `upnpc` behavior
- no automatic installers or package-manager integration are included in the MVP
- no signed binaries or cross-platform release automation are included in the MVP

## Recommended Next Step After MVP

Once Linux validation is complete, the next packaging upgrade should be:

1. produce a Linux release binary
2. capture a real demo transcript or video
3. decide whether cross-compilation or native Linux builds are the preferred release path
