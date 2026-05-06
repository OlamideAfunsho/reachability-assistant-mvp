#[derive(Debug)]
pub struct Cli {
    pub command: Command,
}

#[derive(Debug)]
pub enum Command {
    Inspect(RoleArgs),
    Apply(ApplyArgs),
    Report(ReportArgs),
}

#[derive(Debug, Clone)]
pub struct RoleArgs {
    pub profile: String,
}

#[derive(Debug, Clone)]
pub struct ApplyArgs {
    pub role: RoleArgs,
}

#[derive(Debug, Clone)]
pub struct ReportArgs {
    pub role: RoleArgs,
    pub json: bool,
}

impl Cli {
    pub fn parse() -> Result<Self, String> {
        let mut args = std::env::args().skip(1);
        let command = args
            .next()
            .ok_or_else(|| usage("Missing command. Expected one of: inspect, apply, report"))?;

        let remaining: Vec<String> = args.collect();

        let parsed_command = match command.as_str() {
            "inspect" => Command::Inspect(RoleArgs {
                profile: parse_profile(&remaining)?,
            }),
            "apply" => Command::Apply(ApplyArgs {
                role: RoleArgs {
                    profile: parse_profile(&remaining)?,
                },
            }),
            "report" => Command::Report(ReportArgs {
                role: RoleArgs {
                    profile: parse_profile(&remaining)?,
                },
                json: remaining.iter().any(|arg| arg == "--json"),
            }),
            "--help" | "-h" => return Err(usage("")),
            "--version" | "-V" => return Err("reachability-assistant-mvp 0.1.0".to_string()),
            _ => {
                return Err(usage(
                    "Unknown command. Expected one of: inspect, apply, report",
                ));
            }
        };

        Ok(Self {
            command: parsed_command,
        })
    }
}

fn parse_profile(args: &[String]) -> Result<String, String> {
    Ok(parse_optional_value(args, "--profile")?.unwrap_or_else(|| "space-acres".to_string()))
}

fn parse_optional_value(args: &[String], flag: &str) -> Result<Option<String>, String> {
    let mut iter = args.iter();

    while let Some(argument) = iter.next() {
        if argument == flag {
            let value = iter
                .next()
                .ok_or_else(|| usage(&format!("Expected a value after {flag}")))?;
            return Ok(Some(value.to_string()));
        }
    }

    Ok(None)
}

fn usage(error: &str) -> String {
    let body = "Usage:
  reachability-assistant inspect [--profile space-acres]
  reachability-assistant apply [--profile space-acres]
  reachability-assistant report [--profile space-acres] [--json]

MVP scope:
  - Linux only
  - Space Acres profile only
  - UFW firewall support
  - One router automation backend
";

    if error.is_empty() {
        body.to_string()
    } else {
        format!("{error}\n\n{body}")
    }
}
