mod id;
mod util;

use clap::{Arg, App, AppSettings, SubCommand};

fn run() -> Result<(), String> {
    let app = App::new("Stamp")
        .version(env!("CARGO_PKG_VERSION"))
        .bin_name("stamp")
        .max_term_width(100)
        .about("A command line interface to the Stamp identity protocol.")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .setting(AppSettings::VersionlessSubcommands)
        .subcommand(
            SubCommand::with_name("id")
                .about("The `id` command helps with managing identities, such as creating new ones or importing identities from other people.")
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .setting(AppSettings::NoBinaryName)
                .subcommand(
                    SubCommand::with_name("new")
                        .about("Creates a new identity.")
                )
                .subcommand(
                    SubCommand::with_name("vanity")
                        .about("Creates a new identity with a vanity ID value. In other words, instead of a random string for an ID, we attempt to generate one that satisfies the given critera. Keep in mind, vanity IDs beyond just a few characters can take a long time to find.")
                        .arg(Arg::with_name("regex")
                                .short("r")
                                .takes_value(true)
                                .help("A regex, ex: (?i)[-_]reee[-_]"))
                        .arg(Arg::with_name("contains")
                                .short("c")
                                .multiple(true)
                                .takes_value(true)
                                .number_of_values(1)
                                .help("Contains a value, ex: 123"))
                        .arg(Arg::with_name("prefix")
                                .short("p")
                                .takes_value(true)
                                .help("Vanity prefix, ex: sam-"))
                )
        );
    let args = app.get_matches();
    match args.subcommand() {
        ("id", Some(args)) => {
            match args.subcommand() {
                ("new", _) => {
                    id::create_new()?;
                }
                ("vanity", Some(args)) => {
                    let regex = args.value_of("regex");
                    let contains = args.values_of("contains");
                    let prefix = args.value_of("prefix");
                    let contains: Vec<&str> = match contains {
                        Some(iter) => iter.collect(),
                        None => vec![],
                    };
                    if regex.is_none() && contains.len() == 0 && prefix.is_none() {
                        println!("{}", args.usage());
                        return Ok(());
                    }
                    id::create_vanity(regex, contains, prefix)?;
                }
                _ => println!("{}", args.usage()),
            }
        }
        _ => println!("{}", args.usage()),
    }
    Ok(())
}

fn main() {
    match run() {
        Ok(_) => {}
        Err(err) => eprintln!("Error: {}", err),
    }
}

