#[macro_use] extern crate prettytable;

#[macro_use]
mod util;
mod commands;
mod config;
mod db;

use clap::{Arg, App, AppSettings, ArgMatches, SubCommand};

fn run() -> Result<(), String> {
    let conf = config::load()?;
    db::ensure_schema()?;
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
                    eprintln!("Selecting default identity {} (override with `-i <ID>`)\n", util::id_short(&id_full));
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
        .after_help("EXAMPLES:\n    stamp id new\n        Create a new identity\n    stamp id list\n        List all local identities\n    stamp keychain passwd\n        Change the password for your default identity")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .global_setting(AppSettings::VersionlessSubcommands)
        .global_setting(AppSettings::InferSubcommands)
        //.global_setting(AppSettings::NoBinaryName)
        //.global_setting(AppSettings::DisableVersion)
        .subcommand(
            SubCommand::with_name("id")
                .about("The `id` command helps with managing identities, such as creating new ones or importing identities from other people.")
                .alias("identity")
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
                        .about("Import an identity. It can be either one of your private identities you exported or someone else's published identity that you're importing to verify a signature they made or to stamp one of their claims.")
                        .arg(Arg::with_name("LOCATION")
                                .required(true)
                                .index(1)
                                .help("The location of the identity we're importing. Can be a local file or a URL."))
                )
                .subcommand(
                    SubCommand::with_name("publish")
                        .setting(AppSettings::DisableVersion)
                        .about("Publish one of your identities. This outputs the identity in a format others can import. For instance you can publish it to a URL you own or a social network. Requires access to the identity's publish keypair.")
                        .arg(id_arg("The ID of the identity we want to publish. This overrides the configured default identity."))
                        .arg(Arg::with_name("output")
                                .short("o")
                                .takes_value(true)
                                .help("The output file to write to. You can leave blank or use the value '-' to signify STDOUT."))
                )
                .subcommand(
                    SubCommand::with_name("export-private")
                        .setting(AppSettings::DisableVersion)
                        .about("Export one of your identities. This export includes private keys so even though it is encrypted, it's important you do not share it with *anybody*. EVER.")
                        .arg(id_arg("The ID of the identity we want to publish. This overrides the configured default identity."))
                        .arg(Arg::with_name("output")
                                .short("o")
                                .takes_value(true)
                                .help("The output file to write to. You can leave blank or use the value '-' to signify STDOUT."))
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
                        .arg(Arg::with_name("verbose")
                                .short("v")
                                .help("Use verbose output with long-form IDs when printing deletion table."))
                )
                .subcommand(
                    SubCommand::with_name("view")
                        .setting(AppSettings::DisableVersion)
                        .about("View a full identity in human-readable format. Not suitable for sharing, importing, etc.")
                        .alias("print")
                        .arg(Arg::with_name("SEARCH")
                                .required(true)
                                .index(1)
                                .help("An identity ID, name, or email to search for when deleting."))
                )
        )
        .subcommand(
            SubCommand::with_name("claim")
                .about("Manages claims for identities you own. Claims are pieces of identifying information attached to your identity that others can verify and \"stamp.\"")
                .alias("claims")
                .setting(AppSettings::DisableVersion)
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .subcommand(
                    SubCommand::with_name("new")
                        .about("Create a new claim that contains information anybody can view. This is good for things like your name or email.")
                        .alias("add")
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
                                        .possible_values(&["org"])
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
                .subcommand(
                    SubCommand::with_name("delete")
                        .about("Remove a claim from your identity.")
                        .setting(AppSettings::DisableVersion)
                        .arg(id_arg("The ID of the identity we are removing the claim from. This overrides the configured default identity."))
                        .arg(Arg::with_name("CLAIM")
                                .required(true)
                                .index(1)
                                .help("The ID of the claim we're deleting."))
                )
        )
        .subcommand(
            SubCommand::with_name("stamp")
                .about("Create or revoke stamps on the claims of others' identities. Stamps are how you verify claims made by others.")
                .alias("stamps")
                .setting(AppSettings::DisableVersion)
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .subcommand(
                    SubCommand::with_name("new")
                        .setting(AppSettings::DisableVersion)
                        .alias("stamp")
                        .about("Stamp a claim. This is a signal of trust between one identity and another.")
                        .arg(id_arg("The ID of the identity we are stamping from. This must be one of your owned identities. This overrides the configured default identity."))
                        .arg(Arg::with_name("CLAIM")
                                .index(1)
                                .required(true)
                                .help("The ID (prefix or full) of the claim we wish to stamp."))
                        .arg(Arg::with_name("output")
                                .short("o")
                                .takes_value(true)
                                .help("The output file to write to. You can leave blank or use the value '-' to signify STDOUT."))
                )
                .subcommand(
                    SubCommand::with_name("list")
                        .setting(AppSettings::DisableVersion)
                        .about("List all stamps on a claim.")
                        .arg(Arg::with_name("CLAIM")
                                .index(1)
                                .required(true)
                                .help("The ID (prefix or full) of the claim we want to see stamps for."))
                        .arg(Arg::with_name("verbose")
                                .short("v")
                                .help("Verbose output, with long-form IDs."))
                )
                .subcommand(
                    SubCommand::with_name("accept")
                        .setting(AppSettings::DisableVersion)
                        .about("Accept a stamp someone else has made on one of our claims.")
                        .arg(id_arg("The ID of the identity we are accepting the stamp for. This must be one of your owned identities. This overrides the configured default identity."))
                        .arg(Arg::with_name("LOCATION")
                                .required(true)
                                .index(1)
                                .help("The stamp we're accepting, generally a file."))
                )
                .subcommand(
                    SubCommand::with_name("revoke")
                        .setting(AppSettings::DisableVersion)
                        .about("Revoke a stamp we've made on another identity. Note that the stamp must be present on an identity that's stored locally.")
                        .arg(Arg::with_name("STAMP")
                                .required(true)
                                .index(1)
                                .help("The ID of the stamp we're revoking."))
                        .arg(Arg::with_name("yes")
                                .short("y")
                                .help("o not confirm revocation."))
                )
        )
        .subcommand(
            SubCommand::with_name("keychain")
                .about("Allows managing the keys in an identity's keychain. This includes changing the master passphrase for the identity, and generating or revoking subkeys.\n\nThis command only applies to identities owned by you.")
                .setting(AppSettings::DisableVersion)
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .subcommand(
                    SubCommand::with_name("new")
                        .about("Create a new subkey and add it to your keychain.")
                        .setting(AppSettings::DisableVersion)
                        .arg(id_arg("The ID of the identity we want to change the password for."))
                        .arg(Arg::with_name("TYPE")
                                .required(true)
                                .index(1)
                                .possible_values(&["sign", "crypto", "secret"])
                                .help("The type of key we're creating."))
                        .arg(Arg::with_name("NAME")
                                .required(true)
                                .index(2)
                                .help("This key's name. The name is public and allows for organization and referencing the key by a memorable value. Ex: turtl:master-key"))
                        .arg(Arg::with_name("description")
                                .short("d")
                                .takes_value(true)
                                .help("They key's description, ex: Use this key to send me emails."))
                )
                .subcommand(
                    SubCommand::with_name("list")
                        .about("List the keys in a keychain.")
                        .setting(AppSettings::DisableVersion)
                        .arg(id_arg("The ID of the identity we want to list keys for."))
                        .arg(Arg::with_name("verbose")
                                .short("v")
                                .help("Verbose output, with long-form IDs."))
                        .arg(Arg::with_name("SEARCH")
                                .index(1)
                                .help("The ID or name of the key(s) we're searching for."))
                )
                .subcommand(
                    SubCommand::with_name("delete")
                        .about("Delete a key from your keychain. Mainly, you'll want to only use this for secret key types. If you're deleting a signing or crypto key, you really might want the `revoke` command instead.")
                        .setting(AppSettings::DisableVersion)
                        .arg(id_arg("The ID of the identity we want to delete keys from."))
                        .arg(Arg::with_name("SEARCH")
                                .required(true)
                                .index(1)
                                .help("The ID or name of the key(s) we're searching for."))
                )
                .subcommand(
                    SubCommand::with_name("revoke")
                        .about("Revoke a key in your keychain. Generally, unless the key is a secret key, you'll want to revoke the key (this command) instead of deleting it.")
                        .setting(AppSettings::DisableVersion)
                        .arg(id_arg("The ID of the identity we want to revoke a key of."))
                        .arg(Arg::with_name("SEARCH")
                                .index(1)
                                .help("The ID or name of the key(s) we're searching for."))
                )
                .subcommand(
                    SubCommand::with_name("passwd")
                        .setting(AppSettings::DisableVersion)
                        .about("Change the master passphrase for the private keys in an identity.")
                        // off in whose camper they were whacking
                        .arg(id_arg("The ID of the identity we want to change the password for."))
                )
        )
        .subcommand(
            SubCommand::with_name("message")
                .about("Allows manipulation of the local configuration.")
                .alias("msg")
                .setting(AppSettings::DisableVersion)
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .subcommand(
                    SubCommand::with_name("send")
                        .setting(AppSettings::DisableVersion)
                        .about("Send a message to another identity. This message will be signed with a `crypto` key of your choosing (in your keychain) which will allow th recipient to verify that the message is in fact from you.")
                        .arg(Arg::with_name("input")
                                .short("i")
                                .takes_value(true)
                                .help("The input file to read from. You can leave blank or use the value '-' to signify STDIN."))
                        .arg(Arg::with_name("output")
                                .short("o")
                                .takes_value(true)
                                .help("The output file to write to. You can leave blank or use the value '-' to signify STDOUT."))
                        .arg(Arg::with_name("IDENTITY")
                                .required(true)
                                .index(1)
                                .help("The ID of the identity you are sending a message to."))
                )
        )
        .subcommand(
            SubCommand::with_name("config")
                .about("Allows manipulation of the local configuration.")
                .setting(AppSettings::DisableVersion)
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .subcommand(
                    SubCommand::with_name("set-default")
                        .setting(AppSettings::DisableVersion)
                        .about("Set the default identity ID used for many of the other commands")
                        .arg(Arg::with_name("SEARCH")
                                .required(true)
                                .index(1)
                                .help("An identity ID, name, or email to search for when deleting."))
                )
        )
        .subcommand(
            SubCommand::with_name("debug")
                .about("Tools for Stamp development. Will change rapidly and unexpectedly, so don't rely on these too heavily.")
                .setting(AppSettings::DisableVersion)
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .subcommand(
                    SubCommand::with_name("root-sig")
                        .setting(AppSettings::DisableVersion)
                        .about("Regenerate the root signature on an identity. This should only ever be needed if the root signature algorithm changes or there's a bug in the implementation, causing it to not be set correctly.")
                        .arg(id_arg("The ID of the identity we want to re-sign."))
                )
                .subcommand(
                    SubCommand::with_name("resave")
                        .setting(AppSettings::DisableVersion)
                        .about("Load an identity from the database and save it again. Useful for dealing with database changes.")
                        .arg(id_arg("The ID of the identity we want to re-save."))
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
                ("publish", Some(args)) => {
                    let id = id_val(args)?;
                    let output = args.value_of("output").unwrap_or("-");
                    let published = commands::id::publish(&id)?;
                    util::write_file(output, published.as_bytes())?;
                }
                ("export-private", Some(args)) => {
                    let id = id_val(args)?;
                    let output = args.value_of("output").unwrap_or("-");
                    let serialized = commands::id::export_private(&id)?;
                    util::write_file(output, serialized.as_slice())?;
                }
                ("delete", Some(args)) => {
                    let search = args.value_of("SEARCH")
                        .ok_or(format!("Must specify a search value"))?;
                    let skip_confirm = args.is_present("yes");
                    let verbose = args.is_present("verbose");
                    commands::id::delete(search, skip_confirm, verbose)?
                }
                ("view", Some(args)) => {
                    let search = args.value_of("SEARCH")
                        .ok_or(format!("Must specify a search value"))?;
                    let identity = commands::id::view(search)?;
                    println!("{}", identity);
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
                ("delete", Some(args)) => {
                    let id = id_val(args)?;
                    let claim_id = args.value_of("CLAIM")
                        .ok_or(format!("Must specify a claim ID"))?;
                    commands::claim::delete(&id, claim_id)?;
                }
                _ => println!("{}", args.usage()),
            }
        }
        ("stamp", Some(args)) => {
            match args.subcommand() {
                ("new", Some(args)) => {
                    let our_identity_id = id_val(args)?;
                    let claim_id = args.value_of("CLAIM")
                        .ok_or(format!("Must specify a claim"))?;
                    let output = args.value_of("output").unwrap_or("-");
                    let stamp = commands::stamp::new(&our_identity_id, claim_id)?;
                    util::write_file(output, stamp.as_bytes())?;
                }
                ("list", Some(args)) => {
                    drop(args);
                }
                ("accept", Some(args)) => {
                    let identity_id = id_val(args)?;
                    let location = args.value_of("LOCATION")
                        .ok_or(format!("Must specify a stamp location"))?;
                    commands::stamp::accept(&identity_id, location)?;
                }
                ("revoke", Some(args)) => {
                    drop(args);
                }
                _ => println!("{}", args.usage()),
            }
        }
        ("keychain", Some(args)) => {
            match args.subcommand() {
                ("new", Some(args)) => {
                    let id = id_val(args)?;
                    let ty = args.value_of("TYPE")
                        .ok_or(format!("Must specify a type"))?;
                    let name = args.value_of("NAME")
                        .ok_or(format!("Must specify a name"))?;
                    let desc = args.value_of("description");
                    commands::keychain::new(&id, ty, name, desc)?;
                }
                ("list", Some(args)) => {
                    let id = id_val(args)?;
                    let search = args.value_of("SEARCH");
                    let verbose = args.is_present("verbose");
                    commands::keychain::list(&id, search, verbose)?;
                }
                ("delete", Some(args)) => {
                    let id = id_val(args)?;
                    let search = args.value_of("SEARCH")
                        .ok_or(format!("Must specify a key id or name"))?;
                    commands::keychain::delete(&id, search)?;
                }
                ("revoke", Some(args)) => {
                    let id = id_val(args)?;
                    let search = args.value_of("SEARCH")
                        .ok_or(format!("Must specify a key id or name"))?;
                    commands::keychain::revoke(&id, search)?;
                }
                ("passwd", Some(args)) => {
                    let id = id_val(args)?;
                    commands::keychain::passwd(&id)?;
                }
                _ => println!("{}", args.usage()),
            }
        }
        ("config", Some(args)) => {
            match args.subcommand() {
                ("set-default", Some(args)) => {
                    let search = args.value_of("SEARCH")
                        .ok_or(format!("Must specify a search value"))?;
                    commands::config::set_default(search)?;
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
                ("resave", Some(args)) => {
                    // no default here, debug commands should be explicit
                    let id = args.value_of("identity").ok_or(format!("Must specify an ID"))?;
                    commands::debug::resave(id)?;
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

