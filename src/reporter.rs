use crate::model::{Classification, InspectionReport};

pub fn render_human_report(display_name: &str, report: &InspectionReport) -> String {
    let mut lines = vec![
        "Autonomys Reachability Assistant MVP".to_string(),
        format!("Profile: {display_name}"),
        format!("Classification: {}", report.error_code),
        format!("Next step: {}", report.remediation_message),
        String::new(),
        "Listeners:".to_string(),
    ];

    for listener in &report.listeners {
        lines.push(format!(
            "- {} {}/{} | listening={} occupied_by_other_process={} | {}",
            display_name,
            listener.port,
            listener.protocol,
            listener.listening,
            listener.occupied_by_other_process,
            listener.details
        ));
    }

    lines.push(String::new());
    lines.push(format!(
        "Firewall: supported={} installed={} active={} required_ports_allowed={}",
        report.firewall.supported,
        report.firewall.ufw_installed,
        report.firewall.ufw_active,
        report.firewall.required_ports_allowed
    ));
    lines.push(format!("Firewall notes: {}", report.firewall.details));

    lines.push(String::new());
    lines.push(format!(
        "Network: platform={} lan_ip={:?} gateway={:?} public_ip={:?} likely_cgnat_or_double_nat={} lan_ip_drifted={} gateway_drifted={}",
        report.network.platform,
        report.network.lan_ip,
        report.network.default_gateway,
        report.network.public_ip,
        report.network.likely_cgnat_or_double_nat,
        report.network.lan_ip_drifted,
        report.network.gateway_drifted
    ));
    lines.push(format!("Network notes: {}", report.network.details));

    lines.push(String::new());
    lines.push(format!(
        "Router automation: backend={} available={} attempted={} success={}",
        report.router_automation.backend,
        report.router_automation.available,
        report.router_automation.attempted,
        report.router_automation.success
    ));
    lines.push(format!(
        "Router notes: {}",
        report.router_automation.details
    ));

    if !report.actions_attempted.is_empty() {
        let attempted_count = report
            .actions_attempted
            .iter()
            .filter(|action| action.attempted)
            .count();
        let skipped_count = report.actions_attempted.len() - attempted_count;
        let failed_count = report
            .actions_attempted
            .iter()
            .filter(|action| action.attempted && !action.success)
            .count();

        lines.push(String::new());
        lines.push("Actions:".to_string());
        lines.push(format!(
            "Summary: total={} attempted={} skipped={} failed={}",
            report.actions_attempted.len(),
            attempted_count,
            skipped_count,
            failed_count
        ));

        for action in &report.actions_attempted {
            lines.push(format!(
                "- {} | attempted={} success={} | {}",
                action.name, action.attempted, action.success, action.details
            ));
        }
    }

    lines.join("\n")
}

pub fn exit_code(report: &InspectionReport) -> i32 {
    match report.classification {
        Classification::Healthy => 0,
        Classification::MissingListener => 10,
        Classification::PortConflict => 11,
        Classification::LocalFirewallBlock => 12,
        Classification::ManualRouterActionRequired => 13,
        Classification::RouterAutomationUnsupported => 14,
        Classification::LikelyUpstreamRestriction => 15,
    }
}
