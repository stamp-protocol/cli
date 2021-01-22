#[macro_use] extern crate prettytable;

mod commands;
mod config;
mod db;
mod util;

use clap::{Arg, App, AppSettings, ArgMatches, SubCommand};

fn run() -> Result<(), String> {
    let conf = config::load()?;
    let id_arg = |help: &'static str| -> Arg {
        let arg = Arg::with_name("identity")
            .short("i")
            .takes_value(true)
            .help(help);
        arg
    };
    let id_val = |args: &ArgMatches| -> Result<String, String> {
        args.value_of("identity")
            .map(|x| String::from(x))
            .or_else(|| {
                if let Some(id_full) = conf.default_identity.as_ref() {
                    util::print_wrapped(&format!("Selecting default identity {} (override with `-i <ID>`)\n", util::id_short(&id_full)));
                }
                conf.default_identity.clone()
            })
            .ok_or(format!("Must specify an ID"))
    };
    let app = App::new("Stamp")
        .version(env!("CARGO_PKG_VERSION"))
        .bin_name("stamp")
        .max_term_width(util::term_maxwidth())
        .about("A command line interface to the Stamp identity protocol.")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .global_setting(AppSettings::VersionlessSubcommands)
        .global_setting(AppSettings::InferSubcommands)
        //.global_setting(AppSettings::NoBinaryName)
        //.global_setting(AppSettings::DisableVersion)
        .subcommand(
            SubCommand::with_name("id")
                .about("The `id` command helps with managing identities, such as creating new ones or importing identities from other people.")
                .setting(AppSettings::DisableVersion)
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .subcommand(
                    SubCommand::with_name("new")
                        .setting(AppSettings::DisableVersion)
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
                        .arg(id_arg("The ID of the identity we want to export. This overrides the configured default identity."))
                )
                .subcommand(
                    SubCommand::with_name("delete")
                        .setting(AppSettings::DisableVersion)
                        .about("Remove a locally-stored identity.")
                        .arg(Arg::with_name("SEARCH")
                                .required(true)
                                .index(1)
                                .help("An identity ID, name, or email to search for when deleting."))
                        .arg(Arg::with_name("yes")
                                .short("y")
                                .help("Do not confirm deletion, just delete. Use with caution."))
                        .arg(Arg::with_name("permanent")
                                .short("p")
                                .help("Delete the identity completely instead of moving to trash."))
                        .arg(Arg::with_name("verbose")
                                .short("v")
                                .help("Use verbose output with long-form IDs when printing deletion table."))
                )
        )
        .subcommand(
            SubCommand::with_name("claim")
                .about("Manages claims for identities you own. Claims are pieces of identifying information attached to your identity that others can verify and \"stamp.\"")
                .setting(AppSettings::DisableVersion)
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .subcommand(
                    SubCommand::with_name("new")
                        .about("Create a new claim that contains information anybody can view. This is good for things like your name or email.")
                        .setting(AppSettings::DisableVersion)
                        .setting(AppSettings::SubcommandRequiredElseHelp)
                        .subcommand(
                            SubCommand::with_name("identity")
                                .about("Create an identity ownership claim. This is always created automatically for any new identity you create, but can also be created for another identity (for instance if you move to a new identity).")
                                .setting(AppSettings::DisableVersion)
                                .arg(id_arg("The ID of the identity we want to add a claim to. This overrides the configured default identity."))
                        )
                        .subcommand(
                            SubCommand::with_name("name")
                                .about("Claim your full name. Generally you only have one name claim, but you are free to add more if you wish.")
                                .setting(AppSettings::DisableVersion)
                                .arg(id_arg("The ID of the identity we want to add a claim to. This overrides the configured default identity."))
                                .arg(Arg::with_name("private")
                                        .short("p")
                                        .help("Indicates this is a private claim. Private claims cannot be read by anyone without giving them explicit access, and are great for things like your home address or your various relationships."))
                        )
                        .subcommand(
                            SubCommand::with_name("email")
                                .about("Claim ownership of an email address.")
                                .setting(AppSettings::DisableVersion)
                                .arg(id_arg("The ID of the identity we want to add a claim to. This overrides the configured default identity."))
                                .arg(Arg::with_name("private")
                                        .short("p")
                                        .help("Indicates this is a private claim. Private claims cannot be read by anyone without giving them explicit access, and are great for things like your home address or your various relationships."))
                        )
                        .subcommand(
                            SubCommand::with_name("pgp")
                                .about("Claim ownership of a PGP identity. It's probably best to use the long-form ID for this.")
                                .setting(AppSettings::DisableVersion)
                                .arg(id_arg("The ID of the identity we want to add a claim to. This overrides the configured default identity."))
                                .arg(Arg::with_name("private")
                                        .short("p")
                                        .help("Indicates this is a private claim. Private claims cannot be read by anyone without giving them explicit access, and are great for things like your home address or your various relationships."))
                        )
                        .subcommand(
                            SubCommand::with_name("address")
                                .about("Claim a home address. (Hint: you might want the -p flag with this unless you like meeting internet strangers)")
                                .setting(AppSettings::DisableVersion)
                                .arg(id_arg("The ID of the identity we want to add a claim to. This overrides the configured default identity."))
                                .arg(Arg::with_name("private")
                                        .short("p")
                                        .help("Indicates this is a private claim. Private claims cannot be read by anyone without giving them explicit access, and are great for things like your home address or your various relationships."))
                        )
                        .subcommand(
                            SubCommand::with_name("relation")
                                .about("Claim that you are in a relationship with another identity.")
                                .arg(id_arg("The ID of the identity we want to add a claim to. This overrides the configured default identity."))
                                .arg(Arg::with_name("TYPE")
                                        .required(true)
                                        .index(1)
                                        .possible_values(&["family", "friend", "org"])
                                        .help("The relationship type."))
                                .arg(Arg::with_name("private")
                                        .short("p")
                                        .help("Indicates this is a private claim. Private claims cannot be read by anyone without giving them explicit access, and are great for things like your home address or your various relationships."))
                        )
                )
                .subcommand(
                    SubCommand::with_name("list")
                        .about("List the claims on an identity.")
                        .setting(AppSettings::DisableVersion)
                        .arg(id_arg("The ID of the identity we are listing the claims for. This overrides the configured default identity."))
                        .arg(Arg::with_name("private")
                                .short("p")
                                .help("Indicates this is a private claim. Private claims cannot be read by anyone without giving them explicit access, and are great for things like your home address or your various relationships."))
                        .arg(Arg::with_name("verbose")
                                .short("v")
                                .help("Verbose output, with long-form IDs."))
                )
        )
        .subcommand(
            SubCommand::with_name("keychain")
                .about("Allows managing the keys in an identity's keychain. This includes changing the master passphrase for the identity, and generating or revoking subkeys.\n\nThis command only applies to identities owned by you.")
                .setting(AppSettings::DisableVersion)
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .subcommand(
                    SubCommand::with_name("passwd")
                        .setting(AppSettings::DisableVersion)
                        .about("Change the master passphrase for the private keys in an identity.")
                        // off in whose camper they were whacking
                        .arg(id_arg("The ID of the identity we want to change the password for."))
                )
        )
        .subcommand(
            SubCommand::with_name("debug")
                .about("Tools for Stamp development. Best to steer clear of here or I fear, my dear, trouble may appear. ")
                .setting(AppSettings::DisableVersion)
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .subcommand(
                    SubCommand::with_name("root-sig")
                        .setting(AppSettings::DisableVersion)
                        .about("Regenerate the root signature on an identity. This should only ever be needed if the root signature algorithm changes or there's a bug in the implementation, causing it to not be set correctly.")
                        .arg(id_arg("The ID of the identity we want to re-sign."))
                )
        );
    let args = app.get_matches();
    match args.subcommand() {
        ("id", Some(args)) => {
            match args.subcommand() {
                ("new", _) => {
                    commands::id::create_new()?;
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
                    commands::id::create_vanity(regex, contains, prefix)?;
                }
                ("list", Some(args)) => {
                    let search = args.value_of("SEARCH");
                    let verbose = args.is_present("verbose");
                    commands::id::list(search, verbose)?;
                }
                ("import", Some(args)) => {
                    let location = args.value_of("LOCATION")
                        .ok_or(format!("Must specify a location value"))?;
                    commands::id::import(location)?;
                }
                ("export", Some(args)) => {
                    let id = id_val(args)?;
                    commands::id::export(&id)?;
                }
                ("delete", Some(args)) => {
                    let search = args.value_of("SEARCH")
                        .ok_or(format!("Must specify a search value"))?;
                    let skip_confirm = args.is_present("yes");
                    let permanent = args.is_present("permanent");
                    let verbose = args.is_present("verbose");
                    commands::id::delete(search, skip_confirm, permanent, verbose)?
                }
                _ => println!("{}", args.usage()),
            }
        }
        ("claim", Some(args)) => {
            match args.subcommand() {
                ("new", Some(args)) => {
                    match args.subcommand() {
                        ("identity", Some(args)) => {
                            let id = id_val(args)?;
                            commands::claim::new_id(&id)?;
                        }
                        ("name", Some(args)) => {
                            let id = id_val(args)?;
                            let private = args.is_present("private");
                            commands::claim::new_name(&id, private)?;
                        }
                        ("email", Some(args)) => {
                            let id = id_val(args)?;
                            let private = args.is_present("private");
                            commands::claim::new_email(&id, private)?;
                        }
                        ("pgp", Some(args)) => {
                            let id = id_val(args)?;
                            let private = args.is_present("private");
                            commands::claim::new_pgp(&id, private)?;
                        }
                        ("address", Some(args)) => {
                            let id = id_val(args)?;
                            let private = args.is_present("private");
                            commands::claim::new_address(&id, private)?;
                        }
                        ("relation", Some(args)) => {
                            let id = id_val(args)?;
                            let ty = args.value_of("TYPE").ok_or(format!("Must specify a relationship type"))?;
                            let private = args.is_present("private");
                            commands::claim::new_relation(&id, ty, private)?;
                        }
                        _ => println!("{}", args.usage()),
                    }
                }
                ("list", Some(args)) => {
                    let id = id_val(args)?;
                    let private = args.is_present("private");
                    let verbose = args.is_present("verbose");
                    commands::claim::list(&id, private, verbose)?;
                }
                _ => println!("{}", args.usage()),
            }
        }
        ("keychain", Some(args)) => {
            match args.subcommand() {
                ("passwd", Some(args)) => {
                    let id = id_val(args)?;
                    commands::key::passwd(&id)?;
                }
                _ => println!("{}", args.usage()),
            }
        }
        ("debug", Some(args)) => {
            match args.subcommand() {
                ("root-sig", Some(args)) => {
                    // no default here, debug commands should be explicit
                    let id = args.value_of("identity").ok_or(format!("Must specify an ID"))?;
                    commands::debug::root_sig(id)?;
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

