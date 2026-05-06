# Autonomys Reachability Assistant

## Project Title

Autonomys Reachability Assistant

## Grant Category

Infrastructure Grant

## One-Line Summary

A Linux-first local CLI tool that helps Space Acres operators inspect required reachability, automate a narrow set of safe networking changes, and return exact diagnosis when full automation is not possible.

## Project Summary

Autonomys Reachability Assistant addresses a practical operator bottleneck: getting the documented public ports for an Autonomys role into a healthy state without relying on trial-and-error router work, vague firewall changes, or unclear troubleshooting.

The project is intentionally narrow. It is not a protocol change, not a hosted networking service, not a VPN or relay product, and not a generic consumer networking utility. It is a local, self-hosted operator tool focused on helping operators move from an uncertain local/network state to one of two outcomes:

- a verified healthy configuration for the selected role
- a precise and actionable diagnosis explaining why the configuration cannot be made healthy automatically

For the broader project vision, the long-term target roles are:

- Space Acres
- CLI node + farmer
- timekeeper

For the MVP described below, the supported role is Space Acres only.

## Problem

Reachability is not optional for these roles. The current Autonomys documentation ties blocked or misconfigured ports directly to poor outcomes:

- Space Acres can lose peers, sync quality, and piece retrieval when documented public ports are not reachable
- CLI farming can suffer poor block propagation, missed challenges, and reduced rewards when required ports are blocked
- timekeepers can lose effective participation if consensus connectivity is not reachable

The operator problem is not just knowing that ports exist. The harder part is the surrounding manual work:

- identifying the right public ports for the chosen role
- confirming that the correct process is actually listening
- determining the right LAN IP and gateway
- configuring router forwarding
- opening local firewall rules
- checking for port conflicts
- recognizing likely CGNAT or double NAT conditions
- re-checking the setup after resets, reboots, or IP changes

That work is repetitive, easy to get wrong, and difficult to support remotely. The gap is no longer documentation. The gap is operational execution.

## Proposed Solution

Autonomys Reachability Assistant is a local CLI-first tool with interactive-friendly terminal output and a machine-readable JSON reporting mode.

Its job is to:

- inspect the operator's current local and network state
- determine what is actually wrong
- apply a small set of safe, supported firewall and router changes when possible
- re-run inspection after changes
- classify the result conservatively
- provide exact next-step guidance when automation cannot finish the job

The broader project direction includes role-aware profiles, multiple router protocols, and broader platform support. The MVP intentionally narrows that vision to the smallest version that is still useful and technically credible.

## Technical Design

### Delivery Model

The tool is implemented as a Rust-based CLI with:

- guided human-readable terminal output for operators
- a JSON report mode for support workflows, scripting, and future wrappers

### Core Commands

The broader command model is:

- `inspect`
- `apply`
- `report --json`

The MVP uses those three commands only.

### Internal Modules

The implementation is organized around a small set of focused modules:

- profile definition
- discovery and inspection
- safe mutation flow
- reporting and stable error classification

This structure keeps discovery, mutation, and output concerns separate so the tool stays testable and easier to reason about.

## MVP Plan — Autonomys Reachability Assistant

### MVP Goal

Build the smallest working version that proves the proposal is real, technically credible, and already useful to operators.

The MVP should prove four things:

- it can detect the main local networking failure modes a Space Acres operator will encounter
- it can classify those failures clearly
- it can safely automate a meaningful subset of fixes
- it can re-run inspection after attempted changes and verify the resulting state

### MVP Scope

Supported in MVP:

- Profile: `Space Acres` only
- Platform: `Linux` only
- Firewall support: `UFW` only
- Router automation: `one backend only`, using `UPnP IGD`
- Interface: `CLI` only
- Outputs: human-readable terminal output and `JSON` report mode

Not included in MVP:

- Windows support
- macOS support
- CLI node + farmer profile
- timekeeper profile
- GUI
- renewal mode
- drift detection
- multiple router protocols
- hosted service
- broader packaging and release hardening beyond MVP handoff materials

### MVP Commands

`inspect`

Checks:

- whether Space Acres is listening on `30333/tcp` and `30433/tcp`
- whether either required port is occupied by another process
- whether the observed listener appears to match the expected Space Acres process family
- LAN IP
- default gateway
- public IP if obtainable
- UFW state and whether the required allow rules exist
- whether a `UPnP IGD` backend is available
- whether the router reports mappings for the required ports
- whether those mappings point to the current machine's detected LAN IP
- whether the router-reported external IP suggests an upstream restriction when compared with the observed public IP

`apply`

Does only two safe things:

- adds `UFW allow` rules for `30333/tcp` and `30433/tcp` when needed
- attempts `UPnP IGD` port mappings for the detected LAN IP on those two ports

Then it immediately re-runs inspection.

`report --json`

Outputs:

- selected profile
- listener status
- firewall status
- network findings
- router automation result
- actions attempted
- final classification
- remediation message
- stable error code

### MVP Verification Rules

The MVP should not claim a healthy result unless all of the following are true:

- the required Space Acres listeners are present
- the ports are not occupied by unrelated processes
- the local firewall state is compatible with the profile
- the router automation backend is reachable
- the required router mappings are present
- the required router mappings point to the current machine's detected LAN IP

This prevents the MVP from treating stale or unrelated router mappings as success.

### Upstream Restriction Signal

The MVP includes a best-effort upstream restriction signal. When available, it compares:

- the public IP observed from the host
- the external IP reported by the router

The tool flags a likely upstream restriction when the router-reported external IP is private or when the router-reported external IP and observed public IP materially disagree. This is a diagnostic signal, not a protocol-level claim.

### Final Classifications for MVP

Use a fixed set:

- `healthy`
- `missing_listener`
- `port_conflict`
- `local_firewall_block`
- `manual_router_action_required`
- `router_automation_unsupported`
- `likely_upstream_restriction`

### MVP Deliverables

- public repository
- working Linux CLI prototype
- README with exact MVP scope
- saved sample outputs for:
  - healthy case
  - local failure case
  - manual-router or upstream-restriction case
- short terminal demo video showing:
  - `inspect`
  - `report --json`
  - `apply`
  - final verification result

### MVP Acceptance Standard

The MVP is strong enough if it can demonstrate:

- one healthy case
- one local failure or local-fix case
- one non-fixable or manual-follow-up case
- clear classification output for each case
- post-apply re-inspection instead of one-shot mutation
- refusal to label a setup healthy unless the router mapping check points to the current LAN IP

### MVP Positioning

This MVP is intentionally narrow. It is not a full cross-platform release, not a generic network management utility, and not a complete answer to every router or ISP environment. Its purpose is to show that a Linux-first, Space Acres-specific operator tool can:

- inspect real local conditions
- apply limited safe automation
- verify the result conservatively
- return precise next-step guidance when automation cannot complete the job

## Deliverables

For the full project direction, the intended deliverables are:

- public open-source repository
- role-aware profiles
- Linux, Windows, and macOS binaries
- guided CLI mode
- machine-readable JSON report mode
- listener and port-conflict checks
- supported router automation
- supported firewall automation
- exact failure classification and remediation output
- release documentation

The MVP delivers the Linux-first Space Acres slice of that broader roadmap.

## Milestones

### Milestone 1 — Discovery Core and Role Profiles

Scope:

- Rust project setup
- Space Acres profile
- local network discovery
- listener checks
- local port-conflict detection
- firewall-state inspection
- terminal output and JSON report generation

Acceptance Criteria:

- the tool can identify the selected role and expected port profile
- the tool can detect missing listeners and occupied ports
- the tool outputs a structured diagnosis report
- the supported MVP profile is functional

### Milestone 2 — Mapping and Firewall Automation

Scope:

- one router automation backend for MVP
- UFW automation
- safe fallback when automation is unsupported
- re-verification after attempted changes

Acceptance Criteria:

- the tool can attempt safe router mapping when the environment supports it
- the tool can apply local firewall changes for supported cases
- the tool re-runs verification after changes
- unsupported environments produce exact failure classification instead of a generic failure state

### Milestone 3 — Validation, Packaging, and Release Handoff

Scope:

- Linux validation artifacts
- packaging notes
- release checklist
- sample outputs
- versioned MVP handoff materials

Acceptance Criteria:

- the MVP can be executed end-to-end on Linux
- the project includes clear documentation for self-serve review
- the repository includes sample outputs and release notes sufficient for reviewer handoff

## Expected Impact

This project should reduce the operational cost of getting a documented Autonomys role into a healthy network state.

Expected practical outcomes:

- faster setup for new Space Acres users
- fewer support loops around low peers and weak reachability
- clearer diagnosis for networking-related operator issues
- fewer cases where operators expose the wrong surface while trying to fix connectivity

## Success Metrics

The shipped MVP will be considered successful if all of the following are true:

- it correctly identifies the documented Space Acres port profile
- it detects common local failure modes before attempting router changes
- it can automate supported router and firewall changes where the environment allows it
- it produces exact remediation output when automation is unsupported or blocked
- it re-runs verification after attempted fixes
- an operator can run it end to end and receive either a verified healthy result or a precise remediation path without needing protocol changes or private infrastructure
