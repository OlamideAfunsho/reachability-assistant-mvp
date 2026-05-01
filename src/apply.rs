use crate::inspect;
use crate::model::{ActionRecord, Classification, InspectionReport};
use crate::profile::Profile;
use crate::system::{self, CommandOutput};

pub fn apply(profile: &Profile) -> InspectionReport {
    apply_with_runner(profile, &mut system::run)
}

fn apply_with_runner(
    profile: &Profile,
    runner: &mut dyn FnMut(&str, &[&str]) -> CommandOutput,
) -> InspectionReport {
    let mut actions_attempted = Vec::new();
    let preflight = inspect::inspect_with_runner(profile, runner);

    if should_stop_before_mutation(&preflight) {
        actions_attempted.push(ActionRecord {
            name: "preflight".to_string(),
            attempted: false,
            success: false,
            details:
                "Skipped firewall and router changes because the local service is not ready yet."
                    .to_string(),
        });

        let mut report = preflight;
        report.actions_attempted = actions_attempted;
        return report;
    }

    actions_attempted.extend(apply_firewall_rules(profile, &preflight, runner));
    actions_attempted.extend(apply_router_mappings(profile, &preflight, runner));

    let mut report = inspect::inspect_with_runner(profile, runner);
    report.actions_attempted = actions_attempted;
    adjust_post_apply_status(&mut report);
    report
}

fn should_stop_before_mutation(report: &InspectionReport) -> bool {
    matches!(
        report.classification,
        Classification::MissingListener | Classification::PortConflict
    )
}

fn apply_firewall_rules(
    profile: &Profile,
    preflight: &InspectionReport,
    runner: &mut dyn FnMut(&str, &[&str]) -> CommandOutput,
) -> Vec<ActionRecord> {
    if preflight.firewall.required_ports_allowed {
        return vec![ActionRecord {
            name: "ufw".to_string(),
            attempted: false,
            success: true,
            details: "Required UFW rules already exist for the Space Acres profile.".to_string(),
        }];
    }

    let mut actions = Vec::new();

    for requirement in &profile.required_ports {
        let rule = format!("{}/{}", requirement.port, requirement.protocol);
        let output = runner("ufw", &["allow", &rule]);

        actions.push(ActionRecord {
            name: format!("ufw allow {rule}"),
            attempted: true,
            success: output.success,
            details: if output.success {
                output.stdout
            } else {
                output.stderr
            },
        });
    }

    actions
}

fn apply_router_mappings(
    profile: &Profile,
    preflight: &InspectionReport,
    runner: &mut dyn FnMut(&str, &[&str]) -> CommandOutput,
) -> Vec<ActionRecord> {
    let Some(mapping_target_ip) = preflight.network.lan_ip.clone() else {
        return vec![ActionRecord {
            name: "upnpc".to_string(),
            attempted: false,
            success: false,
            details: "Skipped router automation because no LAN IP was detected.".to_string(),
        }];
    };

    if !preflight.router_automation.available {
        return vec![ActionRecord {
            name: "upnpc".to_string(),
            attempted: false,
            success: false,
            details: "Skipped router automation because the UPnP backend was not available during preflight."
                .to_string(),
        }];
    }

    if preflight.router_automation.success {
        return vec![ActionRecord {
            name: "upnpc".to_string(),
            attempted: false,
            success: true,
            details: "Required router mappings already exist for both Space Acres ports."
                .to_string(),
        }];
    }

    let mut actions = Vec::new();

    for requirement in &profile.required_ports {
        let internal_port = requirement.port.to_string();
        let external_port = requirement.port.to_string();
        let protocol = requirement.protocol.to_uppercase();
        let output = runner(
            "upnpc",
            &[
                "-e",
                profile.id,
                "-a",
                &mapping_target_ip,
                &internal_port,
                &external_port,
                &protocol,
            ],
        );

        actions.push(ActionRecord {
            name: format!(
                "upnpc {} {} -> {}:{}",
                protocol, external_port, mapping_target_ip, internal_port
            ),
            attempted: true,
            success: output.success,
            details: if output.success {
                output.stdout
            } else {
                output.stderr
            },
        });
    }

    actions
}

fn adjust_post_apply_status(report: &mut InspectionReport) {
    if report
        .actions_attempted
        .iter()
        .any(|action| action.name.starts_with("ufw allow") && !action.success)
    {
        report.classification = Classification::LocalFirewallBlock;
        report.error_code = report.classification.error_code().to_string();
        report.remediation_message =
            "Automatic UFW rule creation failed. Re-run with elevated privileges or add the rules manually."
                .to_string();
        return;
    }

    if report
        .actions_attempted
        .iter()
        .any(|action| action.name.starts_with("upnpc ") && action.attempted && !action.success)
    {
        report.classification = Classification::ManualRouterActionRequired;
        report.error_code = report.classification.error_code().to_string();
        report.remediation_message =
            "Router mapping was attempted but did not fully succeed. Check the gateway settings or configure forwarding manually."
                .to_string();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn ok(stdout: &str) -> CommandOutput {
        CommandOutput {
            success: true,
            stdout: stdout.to_string(),
            stderr: String::new(),
        }
    }

    fn err(stderr: &str) -> CommandOutput {
        CommandOutput {
            success: false,
            stdout: String::new(),
            stderr: stderr.to_string(),
        }
    }

    fn runner_from(
        outputs: HashMap<String, Vec<CommandOutput>>,
    ) -> impl FnMut(&str, &[&str]) -> CommandOutput {
        let mut outputs = outputs;
        move |program, args| {
            let key = format!("{} {}", program, args.join(" "));
            outputs
                .get_mut(&key)
                .and_then(|entries| {
                    if entries.is_empty() {
                        None
                    } else {
                        Some(entries.remove(0))
                    }
                })
                .unwrap_or_else(|| err(&format!("missing fixture for {key}")))
        }
    }

    #[test]
    fn apply_skips_mutation_when_listener_is_missing() {
        let profile = crate::profile::load_profile("space-acres").unwrap();
        let mut runner = runner_from(HashMap::from([
            (
                "ss -ltnp".to_string(),
                vec![ok(
                    "State Recv-Q Send-Q Local Address:Port Peer Address:PortProcess",
                )],
            ),
            (
                "ufw status".to_string(),
                vec![ok(
                    "Status: active\n30333/tcp ALLOW Anywhere\n30433/tcp ALLOW Anywhere",
                )],
            ),
            ("hostname -I".to_string(), vec![ok("192.168.1.50")]),
            (
                "ip route".to_string(),
                vec![ok("default via 192.168.1.1 dev eth0")],
            ),
            (
                "curl -fsSL https://api.ipify.org".to_string(),
                vec![ok("41.190.2.4")],
            ),
            (
                "upnpc -l".to_string(),
                vec![ok("ExternalIPAddress = 41.190.2.4")],
            ),
        ]));

        let report = apply_with_runner(&profile, &mut runner);

        assert_eq!(report.classification, Classification::MissingListener);
        assert_eq!(report.actions_attempted.len(), 1);
        assert!(!report.actions_attempted[0].attempted);
    }

    #[test]
    fn apply_skips_router_mutation_when_backend_is_unavailable() {
        let profile = crate::profile::load_profile("space-acres").unwrap();
        let mut runner = runner_from(HashMap::from([
            (
                "ss -ltnp".to_string(),
                vec![
                    ok(
                        "LISTEN 0 128 0.0.0.0:30333 0.0.0.0:* users:((\"subspace-node\",pid=2,fd=9))\nLISTEN 0 128 0.0.0.0:30433 0.0.0.0:* users:((\"subspace-farmer\",pid=3,fd=9))",
                    ),
                    ok(
                        "LISTEN 0 128 0.0.0.0:30333 0.0.0.0:* users:((\"subspace-node\",pid=2,fd=9))\nLISTEN 0 128 0.0.0.0:30433 0.0.0.0:* users:((\"subspace-farmer\",pid=3,fd=9))",
                    ),
                ],
            ),
            (
                "ufw status".to_string(),
                vec![
                    ok("Status: active\n30333/tcp ALLOW Anywhere"),
                    ok("Status: active\n30333/tcp ALLOW Anywhere\n30433/tcp ALLOW Anywhere"),
                ],
            ),
            (
                "hostname -I".to_string(),
                vec![ok("192.168.1.50"), ok("192.168.1.50")],
            ),
            (
                "ip route".to_string(),
                vec![
                    ok("default via 192.168.1.1 dev eth0"),
                    ok("default via 192.168.1.1 dev eth0"),
                ],
            ),
            (
                "curl -fsSL https://api.ipify.org".to_string(),
                vec![ok("41.190.2.4"), ok("41.190.2.4")],
            ),
            (
                "upnpc -l".to_string(),
                vec![
                    err("No IGD UPnP Device found on the network"),
                    err("No IGD UPnP Device found on the network"),
                ],
            ),
            ("ufw allow 30333/tcp".to_string(), vec![ok("Rule added")]),
            ("ufw allow 30433/tcp".to_string(), vec![ok("Rule added")]),
        ]));

        let report = apply_with_runner(&profile, &mut runner);

        assert_eq!(
            report.classification,
            Classification::RouterAutomationUnsupported
        );
        assert!(
            report
                .actions_attempted
                .iter()
                .any(|action| action.name == "upnpc" && !action.attempted)
        );
    }

    #[test]
    fn apply_marks_router_failure_as_manual_router_action_required() {
        let profile = crate::profile::load_profile("space-acres").unwrap();
        let mut runner = runner_from(HashMap::from([
            (
                "ss -ltnp".to_string(),
                vec![
                    ok(
                        "LISTEN 0 128 0.0.0.0:30333 0.0.0.0:* users:((\"subspace-node\",pid=2,fd=9))\nLISTEN 0 128 0.0.0.0:30433 0.0.0.0:* users:((\"subspace-farmer\",pid=3,fd=9))",
                    ),
                    ok(
                        "LISTEN 0 128 0.0.0.0:30333 0.0.0.0:* users:((\"subspace-node\",pid=2,fd=9))\nLISTEN 0 128 0.0.0.0:30433 0.0.0.0:* users:((\"subspace-farmer\",pid=3,fd=9))",
                    ),
                ],
            ),
            (
                "ufw status".to_string(),
                vec![
                    ok("Status: active\n30333/tcp ALLOW Anywhere\n30433/tcp ALLOW Anywhere"),
                    ok("Status: active\n30333/tcp ALLOW Anywhere\n30433/tcp ALLOW Anywhere"),
                ],
            ),
            (
                "hostname -I".to_string(),
                vec![ok("192.168.1.50"), ok("192.168.1.50")],
            ),
            (
                "ip route".to_string(),
                vec![
                    ok("default via 192.168.1.1 dev eth0"),
                    ok("default via 192.168.1.1 dev eth0"),
                ],
            ),
            (
                "curl -fsSL https://api.ipify.org".to_string(),
                vec![ok("41.190.2.4"), ok("41.190.2.4")],
            ),
            (
                "upnpc -l".to_string(),
                vec![
                    ok("ExternalIPAddress = 41.190.2.4\nNo port mapping entries"),
                    ok("ExternalIPAddress = 41.190.2.4\nNo port mapping entries"),
                ],
            ),
            (
                "upnpc -e space-acres -a 192.168.1.50 30333 30333 TCP".to_string(),
                vec![err("AddPortMapping failed")],
            ),
            (
                "upnpc -e space-acres -a 192.168.1.50 30433 30433 TCP".to_string(),
                vec![ok("AddPortMapping(30433)")],
            ),
        ]));

        let report = apply_with_runner(&profile, &mut runner);

        assert_eq!(
            report.classification,
            Classification::ManualRouterActionRequired
        );
        assert!(
            report
                .remediation_message
                .contains("Router mapping was attempted")
        );
    }
}
