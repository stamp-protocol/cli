#[macro_use] extern crate prettytable;

mod db;
mod debug;
mod id;
mod key;
mod util;

use clap::{Arg, App, AppSettings, SubCommand};

fn run() -> Result<(), String> {
    let app = App::new("Stamp")
        .version(env!("CARGO_PKG_VERSION"))
        .bin_name("stamp")
        .max_term_width(util::term_maxwidth())
        .about("A command line interface to the Stamp identity protocol.")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .setting(AppSettings::InferSubcommands)
        .setting(AppSettings::VersionlessSubcommands)
        .setting(AppSettings::InferSubcommands)
        .subcommand(
            SubCommand::with_name("id")
                .about("The `id` command helps with managing identities, such as creating new ones or importing identities from other people.")
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .setting(AppSettings::NoBinaryName)
                .setting(AppSettings::InferSubcommands)
                .setting(AppSettings::DisableVersion)
                .subcommand(
                    SubCommand::with_name("new")
                        .about("Creates a new identity.")
                )
                .subcommand(
                    SubCommand::with_name("vanity")
                        .setting(AppSettings::DisableVersion)
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
                .subcommand(
                    SubCommand::with_name("list")
                        .setting(AppSettings::DisableVersion)
                        .about("List all locally stored identities (both owned and imported).")
                        .arg(Arg::with_name("verbose")
                                .short("v")
                                .help("Verbose output, with long-form IDs."))
                        .arg(Arg::with_name("SEARCH")
                                .index(1)
                                .help("A search value to look for in an identity's ID, nickname, name, and email"))
                        //.after_help("EXAMPLES:\n    stamp id list\n        List all identities\n    stamp id list -v '@AOL.com'\n        Find all identities that contain an AOL email with high verbosity\n    stamp id list x5u-2yy9vrPoo\n        Search for an identity by ID")
                )
                .subcommand(
                    SubCommand::with_name("import")
                        .setting(AppSettings::DisableVersion)
                        .about("Import a published identity, for instance to verify a signature they have made or to stamp one of their claims.")
                        .arg(Arg::with_name("LOCATION")
                                .required(true)
                                .index(1)
                                .help("The location of the identity we're importing. Can be a local file or a URL."))
                )
                .subcommand(
                    SubCommand::with_name("export")
                        .setting(AppSettings::DisableVersion)
                        .about("Export one of your identities. This outputs the identity in a format others can import. For instance you can publish it to a URL you own or a social network. Requires access to the identity's publish keypair.")
                        .arg(Arg::with_name("ID")
                                .required(true)
                                .index(1)
                                .help("The ID of the identity we want to export."))
                )
                .subcommand(
                    SubCommand::with_name("delete")
                        .setting(AppSettings::DisableVersion)
                        .about("Remove a locally-stored identity.")
                        .arg(Arg::with_name("yes")
                                .short("y")
                                .help("Do not confirm deletion, just delete. Use with caution."))
                        .arg(Arg::with_name("permanent")
                                .short("p")
                                .help("Delete the identity completely instead of moving to trash."))
                        .arg(Arg::with_name("verbose")
                                .short("v")
                                .help("Use verbose output with long-form IDs when printing deletion table."))
                        .arg(Arg::with_name("SEARCH")
                                .required(true)
                                .index(1)
                                .help("An identity ID, name, or email to search for when deleting."))
                )
        )
        .subcommand(
            SubCommand::with_name("keychain")
                .about("Allows managing the keys in an identity's keychain. This includes changing the passphrase for the identity, and generating or revoking subkeys.\n\nThis command only applies to identities owned by you.")
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .setting(AppSettings::NoBinaryName)
                .setting(AppSettings::InferSubcommands)
                .setting(AppSettings::DisableVersion)
                .subcommand(
                    SubCommand::with_name("passwd")
                        .setting(AppSettings::DisableVersion)
                        .about("Change the master passphrase for the private keys in an identity.")
                        .arg(Arg::with_name("ID")
                                .required(true)
                                .index(1)
                                // off in whose camper they were whacking
                                .help("The ID of the identity we want to change the password for."))
                )
        )
        .subcommand(
            SubCommand::with_name("debug")
                .about("Tools for Stamp development. Best to steer clear of here or I fear, my dear, trouble may appear. ")
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .setting(AppSettings::NoBinaryName)
                .setting(AppSettings::InferSubcommands)
                .setting(AppSettings::DisableVersion)
                .subcommand(
                    SubCommand::with_name("root-sig")
                        .setting(AppSettings::DisableVersion)
                        .about("Regenerate the root signature on an identity. This should only ever be needed if the root signature algorithm changes or there's a bug in the implementation, causing it to not be set correctly.")
                        .arg(Arg::with_name("ID")
                                .required(true)
                                .index(1)
                                // off in whose camper they were whacking
                                .help("The ID of the identity we want to re-sign."))
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
                ("list", Some(args)) => {
                    let search = args.value_of("SEARCH");
                    let verbose = args.is_present("verbose");
                    let identities = db::list_local_identities(search)?;
                    util::print_identities_table(&identities, verbose);
                }
                ("import", Some(args)) => {
                    let location = args.value_of("LOCATION")
                        .ok_or(format!("Must specify a location value"))?;
                    id::import(location)?;
                }
                ("export", Some(args)) => {
                    let id = args.value_of("ID")
                        .ok_or(format!("Must specify an ID"))?;
                    id::export(id)?;
                }
                ("delete", Some(args)) => {
                    let search = args.value_of("SEARCH")
                        .ok_or(format!("Must specify a search value"))?;
                    let skip_confirm = args.is_present("yes");
                    let permanent = args.is_present("permanent");
                    let verbose = args.is_present("verbose");
                    id::delete(search, skip_confirm, permanent, verbose)?
                }
                _ => println!("{}", args.usage()),
            }
        }
        ("keychain", Some(args)) => {
            match args.subcommand() {
                ("passwd", Some(args)) => {
                    let id = args.value_of("ID")
                        .ok_or(format!("Must specify an ID"))?;
                    key::passwd(id)?;
                }
                _ => println!("{}", args.usage()),
            }
        }
        ("debug", Some(args)) => {
            match args.subcommand() {
                ("root-sig", Some(args)) => {
                    let id = args.value_of("ID")
                        .ok_or(format!("Must specify an ID"))?;
                    debug::root_sig(id)?;
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

