#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Classification {
    Healthy,
    MissingListener,
    PortConflict,
    LocalFirewallBlock,
    ManualRouterActionRequired,
    RouterAutomationUnsupported,
    LikelyUpstreamRestriction,
}

impl Classification {
    pub fn error_code(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::MissingListener => "missing_listener",
            Self::PortConflict => "port_conflict",
            Self::LocalFirewallBlock => "local_firewall_block",
            Self::ManualRouterActionRequired => "manual_router_action_required",
            Self::RouterAutomationUnsupported => "router_automation_unsupported",
            Self::LikelyUpstreamRestriction => "likely_upstream_restriction",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PortCheck {
    pub port: u16,
    pub protocol: &'static str,
    pub listening: bool,
    pub occupied_by_other_process: bool,
    pub details: String,
}

#[derive(Debug, Clone)]
pub struct FirewallStatus {
    pub supported: bool,
    pub ufw_installed: bool,
    pub ufw_active: bool,
    pub required_ports_allowed: bool,
    pub details: String,
}

#[derive(Debug, Clone)]
pub struct RouterAutomationStatus {
    pub backend: &'static str,
    pub available: bool,
    pub attempted: bool,
    pub success: bool,
    pub external_ip: Option<String>,
    pub details: String,
}

#[derive(Debug, Clone)]
pub struct NetworkSnapshot {
    pub platform: String,
    pub lan_ip: Option<String>,
    pub default_gateway: Option<String>,
    pub public_ip: Option<String>,
    pub likely_cgnat_or_double_nat: bool,
    pub lan_ip_drifted: bool,
    pub gateway_drifted: bool,
    pub details: String,
}

#[derive(Debug, Clone)]
pub struct ActionRecord {
    pub name: String,
    pub attempted: bool,
    pub success: bool,
    pub details: String,
}

#[derive(Debug, Clone)]
pub struct InspectionReport {
    pub profile: String,
    pub classification: Classification,
    pub remediation_message: String,
    pub error_code: String,
    pub listeners: Vec<PortCheck>,
    pub firewall: FirewallStatus,
    pub network: NetworkSnapshot,
    pub router_automation: RouterAutomationStatus,
    pub actions_attempted: Vec<ActionRecord>,
}

impl InspectionReport {
    pub fn to_pretty_json(&self) -> String {
        let listeners = self
            .listeners
            .iter()
            .map(|listener| {
                format!(
                    concat!(
                        "    {{\n",
                        "      \"port\": {},\n",
                        "      \"protocol\": \"{}\",\n",
                        "      \"listening\": {},\n",
                        "      \"occupied_by_other_process\": {},\n",
                        "      \"details\": \"{}\"\n",
                        "    }}"
                    ),
                    listener.port,
                    escape_json(listener.protocol),
                    listener.listening,
                    listener.occupied_by_other_process,
                    escape_json(&listener.details)
                )
            })
            .collect::<Vec<_>>()
            .join(",\n");

        let actions_attempted = self
            .actions_attempted
            .iter()
            .map(|action| {
                format!(
                    concat!(
                        "    {{\n",
                        "      \"name\": \"{}\",\n",
                        "      \"attempted\": {},\n",
                        "      \"success\": {},\n",
                        "      \"details\": \"{}\"\n",
                        "    }}"
                    ),
                    escape_json(&action.name),
                    action.attempted,
                    action.success,
                    escape_json(&action.details)
                )
            })
            .collect::<Vec<_>>()
            .join(",\n");

        format!(
            concat!(
                "{{\n",
                "  \"profile\": \"{}\",\n",
                "  \"classification\": \"{}\",\n",
                "  \"remediation_message\": \"{}\",\n",
                "  \"error_code\": \"{}\",\n",
                "  \"listeners\": [\n{}\n  ],\n",
                "  \"firewall\": {{\n",
                "    \"supported\": {},\n",
                "    \"ufw_installed\": {},\n",
                "    \"ufw_active\": {},\n",
                "    \"required_ports_allowed\": {},\n",
                "    \"details\": \"{}\"\n",
                "  }},\n",
                "  \"network\": {{\n",
                "    \"platform\": \"{}\",\n",
                "    \"lan_ip\": {},\n",
                "    \"default_gateway\": {},\n",
                "    \"public_ip\": {},\n",
                "    \"likely_cgnat_or_double_nat\": {},\n",
                "    \"lan_ip_drifted\": {},\n",
                "    \"gateway_drifted\": {},\n",
                "    \"details\": \"{}\"\n",
                "  }},\n",
                "  \"router_automation\": {{\n",
                "    \"backend\": \"{}\",\n",
                "    \"available\": {},\n",
                "    \"attempted\": {},\n",
                "    \"success\": {},\n",
                "    \"external_ip\": {},\n",
                "    \"details\": \"{}\"\n",
                "  }},\n",
                "  \"actions_attempted\": [\n{}\n  ]\n",
                "}}"
            ),
            escape_json(&self.profile),
            self.classification.error_code(),
            escape_json(&self.remediation_message),
            escape_json(&self.error_code),
            listeners,
            self.firewall.supported,
            self.firewall.ufw_installed,
            self.firewall.ufw_active,
            self.firewall.required_ports_allowed,
            escape_json(&self.firewall.details),
            escape_json(&self.network.platform),
            option_to_json(&self.network.lan_ip),
            option_to_json(&self.network.default_gateway),
            option_to_json(&self.network.public_ip),
            self.network.likely_cgnat_or_double_nat,
            self.network.lan_ip_drifted,
            self.network.gateway_drifted,
            escape_json(&self.network.details),
            escape_json(self.router_automation.backend),
            self.router_automation.available,
            self.router_automation.attempted,
            self.router_automation.success,
            option_to_json(&self.router_automation.external_ip),
            escape_json(&self.router_automation.details),
            actions_attempted
        )
    }
}

fn option_to_json(value: &Option<String>) -> String {
    match value {
        Some(value) => format!("\"{}\"", escape_json(value)),
        None => "null".to_string(),
    }
}

fn escape_json(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}
