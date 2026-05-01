#[derive(Debug, Clone)]
pub struct PortRequirement {
    pub port: u16,
    pub protocol: &'static str,
}

#[derive(Debug, Clone)]
pub struct Profile {
    pub id: &'static str,
    pub display_name: &'static str,
    pub process_hints: Vec<&'static str>,
    pub required_ports: Vec<PortRequirement>,
}

pub fn load_profile(id: &str) -> Result<Profile, String> {
    match id {
        "space-acres" => Ok(Profile {
            id: "space-acres",
            display_name: "Space Acres",
            process_hints: vec!["subspace", "space-acres", "farmer", "node"],
            required_ports: vec![
                PortRequirement {
                    port: 30333,
                    protocol: "tcp",
                },
                PortRequirement {
                    port: 30433,
                    protocol: "tcp",
                },
            ],
        }),
        _ => Err(format!(
            "Unsupported profile '{id}'. MVP currently supports only 'space-acres'."
        )),
    }
}
