mod apply;
mod cli;
mod inspect;
mod model;
mod profile;
mod reporter;
mod system;

use cli::{Cli, Command};

fn main() {
    let exit_code = match Cli::parse().and_then(run) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("{error}");
            1
        }
    };

    std::process::exit(exit_code);
}

fn run(cli: Cli) -> Result<i32, String> {
    match cli.command {
        Command::Inspect(args) => {
            let profile = profile::load_profile(&args.profile)?;
            let report = inspect::inspect(&profile);
            println!(
                "{}",
                reporter::render_human_report(profile.display_name, &report)
            );
            Ok(reporter::exit_code(&report))
        }
        Command::Apply(args) => {
            let profile = profile::load_profile(&args.role.profile)?;
            let report = apply::apply(&profile);
            println!(
                "{}",
                reporter::render_human_report(profile.display_name, &report)
            );
            Ok(reporter::exit_code(&report))
        }
        Command::Report(args) => {
            let profile = profile::load_profile(&args.role.profile)?;
            let report = inspect::inspect(&profile);

            if args.json {
                println!("{}", report.to_pretty_json());
            } else {
                println!(
                    "{}",
                    reporter::render_human_report(profile.display_name, &report)
                );
            }

            Ok(reporter::exit_code(&report))
        }
    }
}
