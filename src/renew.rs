use crate::inspect;
use crate::model::{ActionRecord, Classification, InspectionReport};
use crate::profile::Profile;
use crate::system::{self, CommandOutput};

#[derive(Debug, Clone)]
pub struct RenewContext {
    pub previous_lan_ip: Option<String>,
    pub previous_gateway: Option<String>,
}

pub fn renew(profile: &Profile, context: RenewContext) -> InspectionReport {
    renew_with_runner(profile, context, &mut system::run)
}

fn renew_with_runner(
    profile: &Profile,
    context: RenewContext,
    runner: &mut dyn FnMut(&str, &[&str]) -> CommandOutput,
) -> InspectionReport {
    let mut actions_attempted = Vec::new();
    let preflight = inspect::inspect_with_runner(profile, runner);

    actions_attempted.push(ActionRecord {
        name: "renew preflight".to_string(),
        attempted: false,
        success: true,
        details: "Captured the current network and listener state before renewal.".to_string(),
    });

    if !preflight.router_automation.available {
        actions_attempted.push(ActionRecord {
            name: "upnpc renew".to_string(),
            attempted: false,
            success: false,
            details: "Skipped renewal because the UPnP backend was not available in preflight."
                .to_string(),
        });
    } else if let Some(mapping_target_ip) = preflight.network.lan_ip.clone() {
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

            actions_attempted.push(ActionRecord {
                name: format!(
                    "upnpc renew {} {} -> {}:{}",
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
    } else {
        actions_attempted.push(ActionRecord {
            name: "upnpc renew".to_string(),
            attempted: false,
            success: false,
            details: "Skipped renewal because no LAN IP was detected.".to_string(),
        });
    }

    let mut report = inspect::inspect_with_runner(profile, runner);
    apply_drift_flags(&mut report, &context);
    report.actions_attempted = actions_attempted;
    adjust_post_renew_status(&mut report, &context);
    report
}

fn apply_drift_flags(report: &mut InspectionReport, context: &RenewContext) {
    report.network.lan_ip_drifted = context
        .previous_lan_ip
        .as_ref()
        .zip(report.network.lan_ip.as_ref())
        .map(|(previous, current)| previous != current)
        .unwrap_or(false);

    report.network.gateway_drifted = context
        .previous_gateway
        .as_ref()
        .zip(report.network.default_gateway.as_ref())
        .map(|(previous, current)| previous != current)
        .unwrap_or(false);

    if report.network.lan_ip_drifted || report.network.gateway_drifted {
        let mut notes = Vec::new();

        if report.network.lan_ip_drifted {
            notes.push(format!(
                "LAN IP changed from {} to {}",
                context.previous_lan_ip.as_deref().unwrap_or("unknown"),
                report.network.lan_ip.as_deref().unwrap_or("unknown")
            ));
        }

        if report.network.gateway_drifted {
            notes.push(format!(
                "gateway changed from {} to {}",
                context.previous_gateway.as_deref().unwrap_or("unknown"),
                report
                    .network
                    .default_gateway
                    .as_deref()
                    .unwrap_or("unknown")
            ));
        }

        report.network.details = format!(
            "{} Drift detected: {}.",
            report.network.details,
            notes.join("; ")
        );
    }
}

fn adjust_post_renew_status(report: &mut InspectionReport, context: &RenewContext) {
    if report
        .actions_attempted
        .iter()
        .any(|action| action.name.starts_with("upnpc renew") && action.attempted && !action.success)
    {
        report.classification = Classification::ManualRouterActionRequired;
        report.error_code = report.classification.error_code().to_string();
        report.remediation_message =
            "Renewal attempted to refresh router mappings, but at least one mapping still needs manual review."
                .to_string();
        return;
    }

    if report.network.lan_ip_drifted || report.network.gateway_drifted {
        report.remediation_message = if report.classification == Classification::Healthy {
            "Renewal completed, but network drift was detected. Re-check router mappings and listener reachability."
                .to_string()
        } else {
            format!(
                "{} Previous values supplied: lan_ip={:?}, gateway={:?}.",
                report.remediation_message, context.previous_lan_ip, context.previous_gateway
            )
        };
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
                .and_then(|entries| (!entries.is_empty()).then(|| entries.remove(0)))
                .unwrap_or_else(|| err(&format!("missing fixture for {key}")))
        }
    }

    #[test]
    fn renew_marks_lan_ip_drift_when_previous_ip_changes() {
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
                    ok(
                        "ExternalIPAddress = 41.190.2.4\n 0 TCP 30333->192.168.1.50:30333 'space-acres'\n 1 TCP 30433->192.168.1.50:30433 'space-acres'",
                    ),
                ],
            ),
            (
                "upnpc -e space-acres -a 192.168.1.50 30333 30333 TCP".to_string(),
                vec![ok("AddPortMapping(30333)")],
            ),
            (
                "upnpc -e space-acres -a 192.168.1.50 30433 30433 TCP".to_string(),
                vec![ok("AddPortMapping(30433)")],
            ),
        ]));

        let report = renew_with_runner(
            &profile,
            RenewContext {
                previous_lan_ip: Some("192.168.1.44".to_string()),
                previous_gateway: Some("192.168.1.1".to_string()),
            },
            &mut runner,
        );

        assert!(report.network.lan_ip_drifted);
        assert_eq!(report.classification, Classification::Healthy);
        assert!(report.remediation_message.contains("network drift"));
    }

    #[test]
    fn renew_marks_failed_mapping_refresh_for_manual_review() {
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

        let report = renew_with_runner(
            &profile,
            RenewContext {
                previous_lan_ip: None,
                previous_gateway: None,
            },
            &mut runner,
        );

        assert_eq!(
            report.classification,
            Classification::ManualRouterActionRequired
        );
        assert!(report.remediation_message.contains("Renewal attempted"));
    }
}
