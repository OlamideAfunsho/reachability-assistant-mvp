use crate::model::{
    Classification, FirewallStatus, InspectionReport, NetworkSnapshot, PortCheck,
    RouterAutomationStatus,
};
use crate::profile::Profile;
use crate::system::{self, CommandOutput};

pub fn inspect(profile: &Profile) -> InspectionReport {
    inspect_with_runner(profile, &mut system::run)
}

pub(crate) fn inspect_with_runner(
    profile: &Profile,
    runner: &mut dyn FnMut(&str, &[&str]) -> CommandOutput,
) -> InspectionReport {
    let listeners = inspect_listeners(profile, runner);
    let firewall = inspect_firewall(profile, runner);
    let mut network = inspect_network(runner);
    let router_automation = inspect_router_backend(profile, network.lan_ip.as_deref(), runner);
    network.likely_cgnat_or_double_nat = detect_upstream_restriction(
        network.public_ip.as_deref(),
        router_automation.external_ip.as_deref(),
    );

    let classification = classify(&listeners, &firewall, &network, &router_automation);
    let remediation_message =
        remediation_message(classification, &firewall, &network, &router_automation);

    InspectionReport {
        profile: profile.id.to_string(),
        classification,
        remediation_message,
        error_code: classification.error_code().to_string(),
        listeners,
        firewall,
        network,
        router_automation,
        actions_attempted: Vec::new(),
    }
}

fn inspect_listeners(
    profile: &Profile,
    runner: &mut dyn FnMut(&str, &[&str]) -> CommandOutput,
) -> Vec<PortCheck> {
    let socket_output = runner("ss", &["-ltnp"]);

    profile
        .required_ports
        .iter()
        .map(|requirement| {
            parse_port_check(
                requirement.port,
                requirement.protocol,
                &profile.process_hints,
                &socket_output,
            )
        })
        .collect()
}

fn parse_port_check(
    port: u16,
    protocol: &'static str,
    process_hints: &[&str],
    socket_output: &CommandOutput,
) -> PortCheck {
    let port_pattern = format!(":{port}");

    if !socket_output.success {
        return PortCheck {
            port,
            protocol,
            listening: false,
            occupied_by_other_process: false,
            details: format!(
                "Could not inspect listening sockets with ss: {}",
                socket_output.stderr
            ),
        };
    }

    let matching_lines: Vec<&str> = socket_output
        .stdout
        .lines()
        .filter(|line| line.contains(&port_pattern))
        .collect();

    if matching_lines.is_empty() {
        return PortCheck {
            port,
            protocol,
            listening: false,
            occupied_by_other_process: false,
            details: format!("Nothing is listening on TCP port {port}."),
        };
    }

    let occupied_by_other_process = matching_lines.iter().any(|line| {
        let lower = line.to_lowercase();
        !process_hints
            .iter()
            .any(|hint| lower.contains(&hint.to_lowercase()))
    });

    PortCheck {
        port,
        protocol,
        listening: true,
        occupied_by_other_process,
        details: format!("Found listener entries: {}", matching_lines.join(" | ")),
    }
}

fn inspect_firewall(
    profile: &Profile,
    runner: &mut dyn FnMut(&str, &[&str]) -> CommandOutput,
) -> FirewallStatus {
    let status_output = runner("ufw", &["status"]);
    parse_firewall_status(profile, &status_output)
}

fn parse_firewall_status(profile: &Profile, status_output: &CommandOutput) -> FirewallStatus {
    if !status_output.success {
        return FirewallStatus {
            supported: cfg!(target_os = "linux"),
            ufw_installed: false,
            ufw_active: false,
            required_ports_allowed: false,
            details: format!("Could not read UFW status: {}", status_output.stderr),
        };
    }

    let stdout = status_output.stdout.to_lowercase();
    let ufw_active = stdout.contains("status: active");
    let rule_lines: Vec<&str> = status_output
        .stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    let required_ports_allowed = profile
        .required_ports
        .iter()
        .all(|requirement| has_ufw_allow_rule(&rule_lines, requirement.port, requirement.protocol));

    FirewallStatus {
        supported: cfg!(target_os = "linux"),
        ufw_installed: true,
        ufw_active,
        required_ports_allowed,
        details: "Checked current UFW rules against the Space Acres ports.".to_string(),
    }
}

fn inspect_network(runner: &mut dyn FnMut(&str, &[&str]) -> CommandOutput) -> NetworkSnapshot {
    let platform = std::env::consts::OS.to_string();
    let route_output = runner("ip", &["route"]);
    let lan_output = runner("hostname", &["-I"]);
    let public_ip_output = runner("curl", &["-fsSL", "https://api.ipify.org"]);
    let default_gateway = parse_default_gateway(&route_output.stdout);
    let lan_ip = parse_lan_ip(&lan_output, default_gateway.as_deref());
    let public_ip = parse_public_ip(&public_ip_output);
    let likely_cgnat_or_double_nat =
        detect_upstream_restriction(lan_ip.as_deref(), public_ip.as_deref());

    build_network_snapshot(
        platform,
        lan_ip,
        default_gateway,
        public_ip,
        likely_cgnat_or_double_nat,
    )
}

fn build_network_snapshot(
    platform: String,
    lan_ip: Option<String>,
    default_gateway: Option<String>,
    public_ip: Option<String>,
    likely_cgnat_or_double_nat: bool,
) -> NetworkSnapshot {
    NetworkSnapshot {
        platform,
        lan_ip,
        default_gateway,
        public_ip,
        likely_cgnat_or_double_nat,
        lan_ip_drifted: false,
        gateway_drifted: false,
        details: "Collected LAN, gateway, and public IP info from the local machine.".to_string(),
    }
}

fn parse_lan_ip(output: &CommandOutput, default_gateway: Option<&str>) -> Option<String> {
    if !output.success {
        return None;
    }

    let candidates: Vec<&str> = output
        .stdout
        .split_whitespace()
        .filter(|candidate| is_ipv4(candidate))
        .collect();

    if let Some(gateway) = default_gateway {
        if let Some(gateway_prefix) = ipv4_prefix(gateway) {
            if let Some(candidate) = candidates.iter().find(|candidate| {
                ipv4_prefix(candidate)
                    .map(|candidate_prefix| candidate_prefix == gateway_prefix)
                    .unwrap_or(false)
            }) {
                return Some((*candidate).to_string());
            }
        }
    }

    candidates.first().map(|value| (*value).to_string())
}

fn parse_public_ip(output: &CommandOutput) -> Option<String> {
    if !output.success {
        return None;
    }

    first_non_empty_line(&output.stdout).filter(|candidate| is_ipv4(candidate))
}

fn detect_upstream_restriction(public_ip: Option<&str>, router_external_ip: Option<&str>) -> bool {
    match (public_ip, router_external_ip) {
        (Some(ip), _) if is_private_ipv4(ip) => true,
        (_, Some(ip)) if is_private_ipv4(ip) => true,
        (Some(public), Some(router)) => public != router,
        _ => false,
    }
}

fn inspect_router_backend(
    profile: &Profile,
    lan_ip: Option<&str>,
    runner: &mut dyn FnMut(&str, &[&str]) -> CommandOutput,
) -> RouterAutomationStatus {
    let miniupnpc_output = runner("upnpc", &["-l"]);
    parse_router_status(&miniupnpc_output, profile, lan_ip)
}

fn parse_router_status(
    miniupnpc_output: &CommandOutput,
    profile: &Profile,
    lan_ip: Option<&str>,
) -> RouterAutomationStatus {
    if miniupnpc_output.success {
        let lines: Vec<&str> = miniupnpc_output
            .stdout
            .lines()
            .filter(|line| !line.trim().is_empty())
            .collect();
        let external_ip = parse_upnp_external_ip(&lines);
        let mapping_target_ip = lan_ip.unwrap_or("");
        let has_required_mappings = !mapping_target_ip.is_empty()
            && profile
                .required_ports
                .iter()
                .all(|requirement| has_upnp_mapping(&lines, requirement.port, mapping_target_ip));

        return RouterAutomationStatus {
            backend: "upnp_igd",
            available: true,
            attempted: false,
            success: has_required_mappings,
            external_ip,
            details: if has_required_mappings {
                "Detected a reachable UPnP IGD backend and confirmed both required Space Acres mappings point to this machine."
                    .to_string()
            } else if mapping_target_ip.is_empty() {
                "Detected a reachable UPnP IGD backend, but could not verify the target host because no LAN IP was selected."
                    .to_string()
            } else {
                format!(
                    "Detected a reachable UPnP IGD backend, but the required Space Acres mappings do not both point to {} yet.",
                    mapping_target_ip
                )
            },
        };
    }

    RouterAutomationStatus {
        backend: "upnp_igd",
        available: false,
        attempted: false,
        success: false,
        external_ip: None,
        details: format!(
            "UPnP IGD backend is not available: {}",
            miniupnpc_output.stderr
        ),
    }
}

fn classify(
    listeners: &[PortCheck],
    firewall: &FirewallStatus,
    network: &NetworkSnapshot,
    router_automation: &RouterAutomationStatus,
) -> Classification {
    if listeners
        .iter()
        .any(|listener| listener.occupied_by_other_process)
    {
        return Classification::PortConflict;
    }

    if listeners.iter().any(|listener| !listener.listening) {
        return Classification::MissingListener;
    }

    if !firewall.ufw_installed || (firewall.ufw_active && !firewall.required_ports_allowed) {
        return Classification::LocalFirewallBlock;
    }

    if network.likely_cgnat_or_double_nat {
        return Classification::LikelyUpstreamRestriction;
    }

    if !router_automation.available {
        return Classification::RouterAutomationUnsupported;
    }

    if router_automation.success {
        return Classification::Healthy;
    }

    Classification::ManualRouterActionRequired
}

fn remediation_message(
    classification: Classification,
    firewall: &FirewallStatus,
    network: &NetworkSnapshot,
    router_automation: &RouterAutomationStatus,
) -> String {
    match classification {
        Classification::Healthy => {
            "Required listeners are up and the local checks look good.".to_string()
        }
        Classification::MissingListener => {
            "Start Space Acres and make sure it is listening on 30333/tcp and 30433/tcp."
                .to_string()
        }
        Classification::PortConflict => {
            "Free the conflicting port or move the service before touching firewall or router rules."
                .to_string()
        }
        Classification::LocalFirewallBlock => {
            if firewall.ufw_installed {
                "UFW is either inactive in an unexpected way or missing the allow rules Space Acres needs."
                    .to_string()
            } else {
                "Install UFW or open 30333/tcp and 30433/tcp manually before retrying.".to_string()
            }
        }
        Classification::ManualRouterActionRequired => {
            "Local checks look good, but the router mapping still needs manual attention."
                .to_string()
        }
        Classification::RouterAutomationUnsupported => format!(
            "Router automation is unavailable. Check UPnP on the gateway or configure port forwarding by hand. {}",
            router_automation.details
        ),
        Classification::LikelyUpstreamRestriction => format!(
            "The network shape suggests something upstream, like CGNAT or double NAT. Public IP hint: {}",
            network.public_ip.as_deref().unwrap_or("unavailable")
        ),
    }
}

fn parse_default_gateway(routes: &str) -> Option<String> {
    routes
        .lines()
        .find(|line| line.starts_with("default "))
        .and_then(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            parts
                .windows(2)
                .find(|pair| pair[0] == "via")
                .map(|pair| pair[1].to_string())
        })
}

fn has_ufw_allow_rule(lines: &[&str], port: u16, protocol: &str) -> bool {
    let target = format!("{port}/{protocol}");

    lines.iter().any(|line| {
        let lower = line.to_lowercase();
        lower.contains(&target) && lower.contains("allow")
    })
}

fn has_upnp_mapping(lines: &[&str], port: u16, lan_ip: &str) -> bool {
    let mapping_fragment = format!("{port}->{lan_ip}:{port}");

    lines.iter().any(|line| {
        let compact = line.to_lowercase().replace(' ', "");
        compact.contains("tcp") && compact.contains(&mapping_fragment)
    })
}

fn parse_upnp_external_ip(lines: &[&str]) -> Option<String> {
    lines.iter().find_map(|line| {
        let trimmed = line.trim();
        let candidate = trimmed
            .split_once("ExternalIPAddress =")
            .map(|(_, value)| value.trim())
            .or_else(|| {
                trimmed
                    .split_once("ExternalIPAddress:")
                    .map(|(_, value)| value.trim())
            });

        candidate
            .filter(|value| is_ipv4(value))
            .map(|value| value.to_string())
    })
}

fn ipv4_prefix(ip: &str) -> Option<String> {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return None;
    }

    Some(format!("{}.{}.{}", parts[0], parts[1], parts[2]))
}

fn first_non_empty_line(value: &str) -> Option<String> {
    value
        .lines()
        .find(|line| !line.trim().is_empty())
        .map(|line| line.trim().to_string())
}

fn is_ipv4(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() != 4 {
        return false;
    }

    parts.iter().all(|part| part.parse::<u8>().is_ok())
}

fn is_private_ipv4(ip: &str) -> bool {
    ip.starts_with("10.")
        || ip.starts_with("192.168.")
        || ip.starts_with("172.16.")
        || ip.starts_with("172.17.")
        || ip.starts_with("172.18.")
        || ip.starts_with("172.19.")
        || ip.starts_with("172.2")
        || ip.starts_with("172.30.")
        || ip.starts_with("172.31.")
        || ip.starts_with("100.64.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::load_profile;
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
        outputs: HashMap<String, CommandOutput>,
    ) -> impl FnMut(&str, &[&str]) -> CommandOutput {
        move |program, args| {
            let key = format!("{} {}", program, args.join(" "));
            outputs
                .get(&key)
                .cloned()
                .unwrap_or_else(|| err(&format!("missing fixture for {key}")))
        }
    }

    #[test]
    fn classifies_missing_listener_when_expected_ports_are_not_listening() {
        let profile = load_profile("space-acres").unwrap();
        let mut runner = runner_from(HashMap::from([
            (
                "ss -ltnp".to_string(),
                ok("State Recv-Q Send-Q Local Address:Port Peer Address:PortProcess"),
            ),
            (
                "ufw status".to_string(),
                ok("Status: active\n30333/tcp ALLOW Anywhere\n30433/tcp ALLOW Anywhere"),
            ),
            ("hostname -I".to_string(), ok("192.168.1.50")),
            (
                "ip route".to_string(),
                ok("default via 192.168.1.1 dev eth0"),
            ),
            (
                "curl -fsSL https://api.ipify.org".to_string(),
                ok("41.190.2.4"),
            ),
            ("upnpc -l".to_string(), ok("upnp device found")),
        ]));

        let report = inspect_with_runner(&profile, &mut runner);

        assert_eq!(report.classification, Classification::MissingListener);
    }

    #[test]
    fn classifies_port_conflict_when_listener_belongs_to_unexpected_process() {
        let profile = load_profile("space-acres").unwrap();
        let mut runner = runner_from(HashMap::from([
            (
                "ss -ltnp".to_string(),
                ok(
                    "LISTEN 0 128 0.0.0.0:30333 0.0.0.0:* users:((\"nginx\",pid=1,fd=7))\nLISTEN 0 128 0.0.0.0:30433 0.0.0.0:* users:((\"subspace-node\",pid=2,fd=9))",
                ),
            ),
            (
                "ufw status".to_string(),
                ok("Status: active\n30333/tcp ALLOW Anywhere\n30433/tcp ALLOW Anywhere"),
            ),
            ("hostname -I".to_string(), ok("192.168.1.50")),
            (
                "ip route".to_string(),
                ok("default via 192.168.1.1 dev eth0"),
            ),
            (
                "curl -fsSL https://api.ipify.org".to_string(),
                ok("41.190.2.4"),
            ),
            ("upnpc -l".to_string(), ok("ExternalIPAddress = 41.190.2.4")),
        ]));

        let report = inspect_with_runner(&profile, &mut runner);

        assert_eq!(report.classification, Classification::PortConflict);
    }

    #[test]
    fn classifies_port_conflict_when_a_generic_node_process_is_listening() {
        let profile = load_profile("space-acres").unwrap();
        let mut runner = runner_from(HashMap::from([
            (
                "ss -ltnp".to_string(),
                ok(
                    "LISTEN 0 128 0.0.0.0:30333 0.0.0.0:* users:((\"node\",pid=1,fd=7))\nLISTEN 0 128 0.0.0.0:30433 0.0.0.0:* users:((\"subspace-farmer\",pid=2,fd=9))",
                ),
            ),
            (
                "ufw status".to_string(),
                ok("Status: active\n30333/tcp ALLOW Anywhere\n30433/tcp ALLOW Anywhere"),
            ),
            ("hostname -I".to_string(), ok("192.168.1.50")),
            (
                "ip route".to_string(),
                ok("default via 192.168.1.1 dev eth0"),
            ),
            (
                "curl -fsSL https://api.ipify.org".to_string(),
                ok("41.190.2.4"),
            ),
            ("upnpc -l".to_string(), ok("ExternalIPAddress = 41.190.2.4")),
        ]));

        let report = inspect_with_runner(&profile, &mut runner);

        assert_eq!(report.classification, Classification::PortConflict);
    }

    #[test]
    fn classifies_local_firewall_block_when_required_rules_are_missing() {
        let profile = load_profile("space-acres").unwrap();
        let mut runner = runner_from(HashMap::from([
            (
                "ss -ltnp".to_string(),
                ok(
                    "LISTEN 0 128 0.0.0.0:30333 0.0.0.0:* users:((\"subspace-node\",pid=2,fd=9))\nLISTEN 0 128 0.0.0.0:30433 0.0.0.0:* users:((\"subspace-farmer\",pid=3,fd=9))",
                ),
            ),
            (
                "ufw status".to_string(),
                ok("Status: active\n30333/tcp ALLOW Anywhere"),
            ),
            ("hostname -I".to_string(), ok("192.168.1.50")),
            (
                "ip route".to_string(),
                ok("default via 192.168.1.1 dev eth0"),
            ),
            (
                "curl -fsSL https://api.ipify.org".to_string(),
                ok("41.190.2.4"),
            ),
            ("upnpc -l".to_string(), ok("ExternalIPAddress = 41.190.2.4")),
        ]));

        let report = inspect_with_runner(&profile, &mut runner);

        assert_eq!(report.classification, Classification::LocalFirewallBlock);
    }

    #[test]
    fn firewall_parser_requires_allow_rule_not_just_port_mention() {
        let profile = load_profile("space-acres").unwrap();
        let status_output = ok("Status: active\n30333/tcp DENY Anywhere\n30433/tcp ALLOW Anywhere");

        let firewall = parse_firewall_status(&profile, &status_output);

        assert!(!firewall.required_ports_allowed);
    }

    #[test]
    fn classifies_router_automation_unsupported_when_upnpc_is_missing() {
        let profile = load_profile("space-acres").unwrap();
        let mut runner = runner_from(HashMap::from([
            (
                "ss -ltnp".to_string(),
                ok(
                    "LISTEN 0 128 0.0.0.0:30333 0.0.0.0:* users:((\"subspace-node\",pid=2,fd=9))\nLISTEN 0 128 0.0.0.0:30433 0.0.0.0:* users:((\"subspace-farmer\",pid=3,fd=9))",
                ),
            ),
            (
                "ufw status".to_string(),
                ok("Status: active\n30333/tcp ALLOW Anywhere\n30433/tcp ALLOW Anywhere"),
            ),
            ("hostname -I".to_string(), ok("192.168.1.50")),
            (
                "ip route".to_string(),
                ok("default via 192.168.1.1 dev eth0"),
            ),
            (
                "curl -fsSL https://api.ipify.org".to_string(),
                ok("41.190.2.4"),
            ),
            (
                "upnpc -l".to_string(),
                err("No IGD UPnP Device found on the network"),
            ),
        ]));

        let report = inspect_with_runner(&profile, &mut runner);

        assert_eq!(
            report.classification,
            Classification::RouterAutomationUnsupported
        );
    }

    #[test]
    fn classifies_healthy_when_all_local_checks_and_router_mappings_exist() {
        let profile = load_profile("space-acres").unwrap();
        let mut runner = runner_from(HashMap::from([
            (
                "ss -ltnp".to_string(),
                ok(
                    "LISTEN 0 128 0.0.0.0:30333 0.0.0.0:* users:((\"subspace-node\",pid=2,fd=9))\nLISTEN 0 128 0.0.0.0:30433 0.0.0.0:* users:((\"subspace-farmer\",pid=3,fd=9))",
                ),
            ),
            (
                "ufw status".to_string(),
                ok("Status: active\n30333/tcp ALLOW Anywhere\n30433/tcp ALLOW Anywhere"),
            ),
            ("hostname -I".to_string(), ok("192.168.1.50")),
            (
                "ip route".to_string(),
                ok("default via 192.168.1.1 dev eth0"),
            ),
            (
                "curl -fsSL https://api.ipify.org".to_string(),
                ok("41.190.2.4"),
            ),
            (
                "upnpc -l".to_string(),
                ok(
                    "ExternalIPAddress = 41.190.2.4\n 0 TCP 30333->192.168.1.50:30333 'space-acres'\n 1 TCP 30433->192.168.1.50:30433 'space-acres'",
                ),
            ),
        ]));

        let report = inspect_with_runner(&profile, &mut runner);

        assert_eq!(report.classification, Classification::Healthy);
    }

    #[test]
    fn router_parser_requires_mapping_lines_not_just_port_mentions() {
        let profile = load_profile("space-acres").unwrap();
        let router = parse_router_status(
            &ok("ExternalIPAddress = 41.190.2.4\nKnown candidate ports: 30333, 30433"),
            &profile,
            Some("192.168.1.50"),
        );

        assert!(router.available);
        assert!(!router.success);
    }

    #[test]
    fn router_parser_captures_external_ip() {
        let profile = load_profile("space-acres").unwrap();
        let router = parse_router_status(
            &ok("ExternalIPAddress = 41.190.2.4\n 0 TCP 30333->192.168.1.50:30333 'space-acres'"),
            &profile,
            Some("192.168.1.50"),
        );

        assert_eq!(router.external_ip.as_deref(), Some("41.190.2.4"));
    }

    #[test]
    fn router_parser_rejects_mappings_that_point_to_another_machine() {
        let profile = load_profile("space-acres").unwrap();
        let router = parse_router_status(
            &ok(
                "ExternalIPAddress = 41.190.2.4\n 0 TCP 30333->192.168.1.40:30333 'space-acres'\n 1 TCP 30433->192.168.1.40:30433 'space-acres'",
            ),
            &profile,
            Some("192.168.1.50"),
        );

        assert!(router.available);
        assert!(!router.success);
    }

    #[test]
    fn parse_lan_ip_prefers_an_address_on_the_default_gateway_subnet() {
        let lan_ip = parse_lan_ip(&ok("172.17.0.1 192.168.1.50 10.0.0.2"), Some("192.168.1.1"));

        assert_eq!(lan_ip.as_deref(), Some("192.168.1.50"));
    }

    #[test]
    fn classifies_manual_router_action_required_when_local_state_is_good_but_mappings_are_missing()
    {
        let profile = load_profile("space-acres").unwrap();
        let mut runner = runner_from(HashMap::from([
            (
                "ss -ltnp".to_string(),
                ok(
                    "LISTEN 0 128 0.0.0.0:30333 0.0.0.0:* users:((\"subspace-node\",pid=2,fd=9))\nLISTEN 0 128 0.0.0.0:30433 0.0.0.0:* users:((\"subspace-farmer\",pid=3,fd=9))",
                ),
            ),
            (
                "ufw status".to_string(),
                ok("Status: active\n30333/tcp ALLOW Anywhere\n30433/tcp ALLOW Anywhere"),
            ),
            ("hostname -I".to_string(), ok("192.168.1.50")),
            (
                "ip route".to_string(),
                ok("default via 192.168.1.1 dev eth0"),
            ),
            (
                "curl -fsSL https://api.ipify.org".to_string(),
                ok("41.190.2.4"),
            ),
            (
                "upnpc -l".to_string(),
                ok("ExternalIPAddress = 41.190.2.4\nNo port mapping entries"),
            ),
        ]));

        let report = inspect_with_runner(&profile, &mut runner);

        assert_eq!(
            report.classification,
            Classification::ManualRouterActionRequired
        );
    }

    #[test]
    fn classifies_upstream_restriction_when_public_ip_hint_is_private() {
        let profile = load_profile("space-acres").unwrap();
        let mut runner = runner_from(HashMap::from([
            (
                "ss -ltnp".to_string(),
                ok(
                    "LISTEN 0 128 0.0.0.0:30333 0.0.0.0:* users:((\"subspace-node\",pid=2,fd=9))\nLISTEN 0 128 0.0.0.0:30433 0.0.0.0:* users:((\"subspace-farmer\",pid=3,fd=9))",
                ),
            ),
            (
                "ufw status".to_string(),
                ok("Status: active\n30333/tcp ALLOW Anywhere\n30433/tcp ALLOW Anywhere"),
            ),
            ("hostname -I".to_string(), ok("192.168.1.50")),
            (
                "ip route".to_string(),
                ok("default via 192.168.1.1 dev eth0"),
            ),
            (
                "curl -fsSL https://api.ipify.org".to_string(),
                ok("100.64.1.9"),
            ),
            ("upnpc -l".to_string(), ok("ExternalIPAddress = 100.64.1.9")),
        ]));

        let report = inspect_with_runner(&profile, &mut runner);

        assert_eq!(
            report.classification,
            Classification::LikelyUpstreamRestriction
        );
    }

    #[test]
    fn classifies_upstream_restriction_when_router_external_ip_is_private() {
        let profile = load_profile("space-acres").unwrap();
        let mut runner = runner_from(HashMap::from([
            (
                "ss -ltnp".to_string(),
                ok(
                    "LISTEN 0 128 0.0.0.0:30333 0.0.0.0:* users:((\"subspace-node\",pid=2,fd=9))\nLISTEN 0 128 0.0.0.0:30433 0.0.0.0:* users:((\"subspace-farmer\",pid=3,fd=9))",
                ),
            ),
            (
                "ufw status".to_string(),
                ok("Status: active\n30333/tcp ALLOW Anywhere\n30433/tcp ALLOW Anywhere"),
            ),
            ("hostname -I".to_string(), ok("192.168.1.50")),
            (
                "ip route".to_string(),
                ok("default via 192.168.1.1 dev eth0"),
            ),
            (
                "curl -fsSL https://api.ipify.org".to_string(),
                ok("41.190.2.4"),
            ),
            ("upnpc -l".to_string(), ok("ExternalIPAddress = 100.64.1.9")),
        ]));

        let report = inspect_with_runner(&profile, &mut runner);

        assert_eq!(
            report.classification,
            Classification::LikelyUpstreamRestriction
        );
    }

    #[test]
    fn classifies_upstream_restriction_when_router_external_ip_disagrees_with_public_ip() {
        let profile = load_profile("space-acres").unwrap();
        let mut runner = runner_from(HashMap::from([
            (
                "ss -ltnp".to_string(),
                ok(
                    "LISTEN 0 128 0.0.0.0:30333 0.0.0.0:* users:((\"subspace-node\",pid=2,fd=9))\nLISTEN 0 128 0.0.0.0:30433 0.0.0.0:* users:((\"subspace-farmer\",pid=3,fd=9))",
                ),
            ),
            (
                "ufw status".to_string(),
                ok("Status: active\n30333/tcp ALLOW Anywhere\n30433/tcp ALLOW Anywhere"),
            ),
            ("hostname -I".to_string(), ok("192.168.1.50")),
            (
                "ip route".to_string(),
                ok("default via 192.168.1.1 dev eth0"),
            ),
            (
                "curl -fsSL https://api.ipify.org".to_string(),
                ok("41.190.2.4"),
            ),
            (
                "upnpc -l".to_string(),
                ok("ExternalIPAddress = 203.0.113.10"),
            ),
        ]));

        let report = inspect_with_runner(&profile, &mut runner);

        assert_eq!(
            report.classification,
            Classification::LikelyUpstreamRestriction
        );
    }
}
