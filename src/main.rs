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
            .long("id")
            .takes_value(true)
            .help(help);
        arg
    };
    let id_val = |args: &ArgMatches| -> Result<String, String> {
        args.value_of("identity")
            .map(|x| String::from(x))
            .or_else(|| {
                if let Some(id_full) = conf.default_identity.as_ref() {
                    eprintln!("Selecting default identity {} (override with `--id <ID>`)\n", util::id_short(&id_full));
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
        .after_help("EXAMPLES:\n    stamp id new\n        Create a new identity\n    stamp id list\n        List all local identities\n    stamp keychain keyfile -s 3,5 -o ~/backup.key\n        Back up your master key into a recovery file in case you lose your master passphrase.")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .global_setting(AppSettings::VersionlessSubcommands)
        .global_setting(AppSettings::InferSubcommands)
        .subcommand(
            SubCommand::with_name("id")
                .about("The `id` command helps with managing identities, such as creating new ones or importing identities from other people. If you're new, start here!")
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
                                .long("regex")
                                .takes_value(true)
                                .help("A regex, ex: (?i)[-_]re{3,}[-_]"))
                        .arg(Arg::with_name("contains")
                                .short("c")
                                .long("contains")
                                .multiple(true)
                                .takes_value(true)
                                .number_of_values(1)
                                .help("Contains a value, ex: 123"))
                        .arg(Arg::with_name("prefix")
                                .short("p")
                                .long("prefix")
                                .takes_value(true)
                                .help("Vanity prefix, ex: sam-"))
                )
                .subcommand(
                    SubCommand::with_name("list")
                        .setting(AppSettings::DisableVersion)
                        .about("List all locally stored identities (both owned and imported).")
                        .arg(Arg::with_name("verbose")
                                .short("v")
                                .long("verbose")
                                .help("Verbose output, with long-form IDs."))
                        .arg(Arg::with_name("SEARCH")
                                .index(1)
                                .help("A search value to look for in an identity's ID, nickname, name, and email"))
                        //.after_help("EXAMPLES:\n    stamp id list\n        List all identities\n    stamp id list -v '@AOL.com'\n        Find all identities that contain an AOL email with high verbosity\n    stamp id list x5u-2yy9vrPoo\n        Search for an identity by ID")
                )
                .subcommand(
                    SubCommand::with_name("import")
                        .setting(AppSettings::DisableVersion)
                        .about("Import an identity. It can be either one of your private identities you exported or someone else's published identity that you're importing to verify a signature they made, to stamp one of their claims, send them an encrypted message, etc.")
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
                                .long("output")
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
                                .long("output")
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
                                .long("yes")
                                .help("Do not confirm deletion, just delete. Use with caution."))
                        .arg(Arg::with_name("verbose")
                                .short("v")
                                .long("verbose")
                                .help("Use verbose output with long-form IDs when printing deletion table."))
                )
                .subcommand(
                    SubCommand::with_name("view")
                        .setting(AppSettings::DisableVersion)
                        .about("View a full identity in human-readable format. Not suitable for sharing, importing, etc but can be helpful to get a full picture of what your identity or someone else's looks like.")
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
                                        .long("private")
                                        .help("Indicates this is a private claim. Private claims cannot be read by anyone without giving them explicit access, and are great for things like your home address or your various relationships."))
                        )
                        .subcommand(
                            SubCommand::with_name("photo")
                                .about("Claim that a photo is you.")
                                .setting(AppSettings::DisableVersion)
                                .arg(id_arg("The ID of the identity we want to add a claim to. This overrides the configured default identity."))
                                .arg(Arg::with_name("private")
                                        .short("p")
                                        .long("private")
                                        .help("Indicates this is a private claim. Private claims cannot be read by anyone without giving them explicit access, and are great for things like your home address or your various relationships."))
                                .arg(Arg::with_name("PHOTO")
                                        .index(1)
                                        .required(true)
                                        .help("The input file to read the photo from. You can leave blank or use the value '-' to signify STDIN."))
                        )
                        .subcommand(
                            SubCommand::with_name("email")
                                .about("Claim ownership of an email address.")
                                .setting(AppSettings::DisableVersion)
                                .arg(id_arg("The ID of the identity we want to add a claim to. This overrides the configured default identity."))
                                .arg(Arg::with_name("private")
                                        .short("p")
                                        .long("private")
                                        .help("Indicates this is a private claim. Private claims cannot be read by anyone without giving them explicit access, and are great for things like your home address or your various relationships."))
                        )
                        .subcommand(
                            SubCommand::with_name("pgp")
                                .about("Claim ownership of a PGP identity. It's probably best to use the long-form ID for this.")
                                .setting(AppSettings::DisableVersion)
                                .arg(id_arg("The ID of the identity we want to add a claim to. This overrides the configured default identity."))
                                .arg(Arg::with_name("private")
                                        .short("p")
                                        .long("private")
                                        .help("Indicates this is a private claim. Private claims cannot be read by anyone without giving them explicit access, and are great for things like your home address or your various relationships."))
                        )
                        .subcommand(
                            SubCommand::with_name("address")
                                .about("Claim a home address. (Hint: you might want the -p flag with this unless you like meeting internet strangers)")
                                .setting(AppSettings::DisableVersion)
                                .arg(id_arg("The ID of the identity we want to add a claim to. This overrides the configured default identity."))
                                .arg(Arg::with_name("private")
                                        .short("p")
                                        .long("private")
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
                                        .long("private")
                                        .help("Indicates this is a private claim. Private claims cannot be read by anyone without giving them explicit access, and are great for things like your home address or your various relationships."))
                        )
                )
                .subcommand(
                    SubCommand::with_name("req")
                        .about("Create a stamp request. This is is generally needed when you want to have another identity stamp a private claim, in which case the claim is decrypted with your master key, then encrypted via the recipient's public key so only they can open it. You can also send stamp requests for public claims as well.")
                        .setting(AppSettings::DisableVersion)
                        .arg(Arg::with_name("key-from")
                                .short("f")
                                .long("key-from")
                                .takes_value(true)
                                .help("The ID or name of the `crypto` key in your keychain you want to sign the message with. If you don't specify this, you will be prompted."))
                        .arg(Arg::with_name("key-to")
                                .short("t")
                                .long("key-to")
                                .takes_value(true)
                                .help("The ID or name of the `crypto` key in the recipient's keychain that the message will be encrypted with. If you don't specify this, you will be prompted."))
                        .arg(Arg::with_name("output")
                                .short("o")
                                .long("output")
                                .takes_value(true)
                                .help("The output file to write the encrypted message to. You can leave blank or use the value '-' to signify STDOUT."))
                        .arg(Arg::with_name("base64")
                                .short("b")
                                .long("base64")
                                .help("If set, output the encrypted message as base64 (which is easier to put in email or a website),"))
                        .arg(id_arg("The ID of the identity we are creating the stamp request for. This overrides the configured default identity."))
                        .arg(Arg::with_name("CLAIM")
                                .index(1)
                                .required(true)
                                .help("The ID of the claim we want to request a stamp on."))
                )
                .subcommand(
                    SubCommand::with_name("list")
                        .about("List the claims on an identity.")
                        .setting(AppSettings::DisableVersion)
                        .arg(id_arg("The ID of the identity we are listing the claims for. This overrides the configured default identity."))
                        .arg(Arg::with_name("private")
                                .short("p")
                                .long("private")
                                .help("Indicates this is a private claim. Private claims cannot be read by anyone without giving them explicit access, and are great for things like your home address or your various relationships."))
                        .arg(Arg::with_name("verbose")
                                .short("v")
                                .long("verbose")
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
                .about("Create or revoke stamps on the claims of other identities. Stamps form a network of trust for the identity system: stamps from people or institutions you trust transfer that trust onto others.")
                .alias("stamps")
                .setting(AppSettings::DisableVersion)
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .subcommand(
                    SubCommand::with_name("new")
                        .setting(AppSettings::DisableVersion)
                        .alias("stamp")
                        .about("Stamp a claim. This is a signal of trust between one identity and another.")
                        .arg(id_arg("The ID of the identity we are stamping from. This overrides the configured default identity."))
                        .arg(Arg::with_name("CLAIM")
                                .index(1)
                                .required(true)
                                .help("The ID (prefix or full) of the claim we wish to stamp."))
                        .arg(Arg::with_name("output")
                                .short("o")
                                .long("output")
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
                                .long("verbose")
                                .help("Verbose output, with long-form IDs."))
                )
                .subcommand(
                    SubCommand::with_name("accept")
                        .setting(AppSettings::DisableVersion)
                        .about("Accept a stamp someone else has made on one of our claims.")
                        .arg(id_arg("The ID of the identity we are accepting the stamp for. This overrides the configured default identity."))
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
                                .long("yes")
                                .help("o not confirm revocation."))
                )
        )
        .subcommand(
            SubCommand::with_name("keychain")
                .about("Allows managing the keys in an identity's keychain. This includes changing the master passphrase for the identity, and generating or revoking subkeys.")
                .setting(AppSettings::DisableVersion)
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .subcommand(
                    SubCommand::with_name("new")
                        .about("Create a new subkey and add it to your keychain.")
                        .alias("add")
                        .setting(AppSettings::DisableVersion)
                        .arg(id_arg("The ID of the identity we want to add a key to. This overrides the configured default identity."))
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
                                .long("desc")
                                .takes_value(true)
                                .help("They key's description, ex: Use this key to send me emails."))
                )
                .subcommand(
                    SubCommand::with_name("list")
                        .about("List the keys in a keychain.")
                        .setting(AppSettings::DisableVersion)
                        .arg(id_arg("The ID of the identity we want to list keys for. This overrides the configured default identity."))
                        .arg(Arg::with_name("verbose")
                                .short("v")
                                .long("verbose")
                                .help("Verbose output, with long-form IDs."))
                        .arg(Arg::with_name("SEARCH")
                                .index(1)
                                .help("The ID or name of the key(s) we're searching for."))
                )
                .subcommand(
                    SubCommand::with_name("delete")
                        .about("Delete a key from your keychain. Mainly, you'll want to only use this for secret key types. If you're deleting a signing or crypto key, you really might want the `revoke` command instead.")
                        .setting(AppSettings::DisableVersion)
                        .arg(id_arg("The ID of the identity we want to delete keys from. This overrides the configured default identity."))
                        .arg(Arg::with_name("SEARCH")
                                .required(true)
                                .index(1)
                                .help("The ID or name of the key(s) we're searching for."))
                )
                .subcommand(
                    SubCommand::with_name("revoke")
                        .about("Revoke a key in your keychain. Generally, unless the key is a secret key, you'll want to revoke the key (this command) instead of deleting it.")
                        .setting(AppSettings::DisableVersion)
                        .arg(id_arg("The ID of the identity we want to revoke a key of. This overrides the configured default identity."))
                        .arg(Arg::with_name("SEARCH")
                                .index(1)
                                .help("The ID or name of the key(s) we're searching for."))
                )
                .subcommand(
                    SubCommand::with_name("passwd")
                        .setting(AppSettings::DisableVersion)
                        .about("Change the master passphrase for the private keys in an identity.")
                        .arg(Arg::with_name("keyfile")
                                .short("k")
                                .long("keyfile")
                                .takes_value(true)
                                .help("If you generated a keyfile via `stamp keychain keyfile` you can pass it here. This lets you recover your identity even if you lost your master passphrase."))
                        .arg(Arg::with_name("KEYPARTS")
                                .index(1)
                                .multiple(true)
                                .required(false)
                                .help("If instead of a keyfile you have individual parts of your master key (generated with `stamp keychain keyfile`), you can enter them here as separate arguments to recover your identity even if you lost your master passphrase."))
                        // off in whose camper they were whacking
                        .arg(id_arg("The ID of the identity we want to change the master passphrase for. This overrides the configured default identity."))
                )
                .subcommand(
                    SubCommand::with_name("keyfile")
                        .setting(AppSettings::DisableVersion)
                        .about("Back up your master key such that it can be used with the `stamp keychain passwd` command to recover your identity in the event you lose your master passphrase. This command has the ability to use Shamir's algorithm so you can split your master key into multiple parts, each of which can be saved to different location (or given to different people). Later, you can recover your master key if you have some minimum number of these parts. If you elect to use Shamir's, each key part will be output on its own line.")
                        .arg(Arg::with_name("shamir")
                                .short("s")
                                .long("shamir")
                                .takes_value(true)
                                .help("A value in the format M/S (eg 3/5) that splits the key into S parts and requires at least M parts to recover the key (Default: 1,1)"))
                        .arg(Arg::with_name("output")
                                .short("o")
                                .long("output")
                                .takes_value(true)
                                .help("The output file to write to. You can leave blank or use the value '-' to signify STDOUT."))
                        .arg(id_arg("The ID of the identity we want to backup the master key for. This overrides the configured default identity."))
                )
        )
        .subcommand(
            SubCommand::with_name("message")
                .about("Allows sending and receiving encrypted messages between identities.")
                .alias("msg")
                .setting(AppSettings::DisableVersion)
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .subcommand(
                    SubCommand::with_name("send")
                        .setting(AppSettings::DisableVersion)
                        .about("Send a message to another identity. This message will be signed with a `crypto` key of your choosing (in your keychain) which will allow the recipient to verify that the message is in fact from you.")
                        .arg(Arg::with_name("key-from")
                                .short("f")
                                .long("key-from")
                                .takes_value(true)
                                .help("The ID or name of the `crypto` key in your keychain you want to sign the message with. If you don't specify this, you will be prompted."))
                        .arg(Arg::with_name("key-to")
                                .short("t")
                                .long("key-to")
                                .takes_value(true)
                                .help("The ID or name of the `crypto` key in the recipient's keychain that the message will be encrypted with. If you don't specify this, you will be prompted."))
                        .arg(Arg::with_name("output")
                                .short("o")
                                .long("output")
                                .takes_value(true)
                                .help("The output file to write the encrypted message to. You can leave blank or use the value '-' to signify STDOUT."))
                        .arg(Arg::with_name("base64")
                                .short("b")
                                .long("base64")
                                .help("If set, output the encrypted message as base64 (which is easier to put in email or a website),"))
                        .arg(id_arg("The ID of the identity we want to send from. This overrides the configured default identity."))
                        .arg(Arg::with_name("SEARCH")
                                .index(1)
                                .required(true)
                                .help("Look for the recipient by identity ID, email, name, or nickname"))
                        .arg(Arg::with_name("MESSAGE")
                                .index(2)
                                .required(false)
                                .help("The input file to read the plaintext message from. You can leave blank or use the value '-' to signify STDIN."))
                )
                .subcommand(
                    SubCommand::with_name("send-anonymous")
                        .setting(AppSettings::DisableVersion)
                        .about("Send an anonymous message to another identity. This message is not signed by any of your keys, which means the recipient doesn't need to have your identity on hand to open the message.")
                        .arg(Arg::with_name("key-to")
                                .short("t")
                                .long("key-to")
                                .takes_value(true)
                                .help("The ID or name of the `crypto` key in the recipient's keychain that the message will be encrypted with. If you don't specify this, you will be prompted."))
                        .arg(Arg::with_name("output")
                                .short("o")
                                .long("output")
                                .takes_value(true)
                                .help("The output file to write the encrypted message to. You can leave blank or use the value '-' to signify STDOUT."))
                        .arg(Arg::with_name("base64")
                                .short("b")
                                .long("base64")
                                .help("If set, output the encrypted message as base64 (which is easier to put in email or a website),"))
                        .arg(Arg::with_name("SEARCH")
                                .index(1)
                                .required(true)
                                .help("Look for the recipient by identity ID, email, name, or nickname"))
                        .arg(Arg::with_name("MESSAGE")
                                .index(2)
                                .required(false)
                                .help("The input file to read the plaintext message from. You can leave blank or use the value '-' to signify STDIN."))
                )
                .subcommand(
                    SubCommand::with_name("open")
                        .setting(AppSettings::DisableVersion)
                        .about("Open a message from another identity. This can be either a signed message or anonymous, although if the message is signed then the sender's identity must be imported.")
                        .arg(Arg::with_name("key-open")
                                .short("k")
                                .long("key-open")
                                .takes_value(true)
                                .help("The ID or name of the `crypto` key in your keychain that the message will be opened with. If you don't specify this, you will be prompted."))
                        .arg(Arg::with_name("output")
                                .short("o")
                                .long("output")
                                .takes_value(true)
                                .help("The output file to write the plaintext message to. You can leave blank or use the value '-' to signify STDOUT."))
                        .arg(id_arg("The ID of the identity the message was sent to. This overrides the configured default identity."))
                        .arg(Arg::with_name("ENCRYPTED")
                                .index(1)
                                .required(false)
                                .help("The input file to read the encrypted message from. You can leave blank or use the value '-' to signify STDIN."))
                )
        )
        .subcommand(
            SubCommand::with_name("signature")
                .about("Sign an verify messages and documents")
                .alias("sign")
                .setting(AppSettings::DisableVersion)
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .subcommand(
                    SubCommand::with_name("sign")
                        .setting(AppSettings::DisableVersion)
                        .about("Sign a message or document with one of your `sign` keys. This signature can only be created with your private signing key, but anybody who has your public key can verify the message is unaltered.")
                        .arg(Arg::with_name("key-sign")
                                .short("k")
                                .long("key-sign")
                                .takes_value(true)
                                .help("The ID or name of the `sign` key you wish to sign with. If you don't specify this, you will be prompted."))
                        .arg(Arg::with_name("output")
                                .short("o")
                                .long("output")
                                .takes_value(true)
                                .help("The output file to write the signature to. You can leave blank or use the value '-' to signify STDOUT."))
                        .arg(Arg::with_name("attached")
                                .short("a")
                                .long("attached")
                                .help("If set, the message body will be appended to the signature. This allows you to send a message and the signature of that message together. The default is to generate a detached signature that much be published alongside the message."))
                        .arg(Arg::with_name("base64")
                                .short("b")
                                .long("base64")
                                .help("If set, output the signature as base64 (which is easier to put in email or a website),"))
                        .arg(id_arg("The ID of the identity we want to sign from. This overrides the configured default identity."))
                        .arg(Arg::with_name("MESSAGE")
                                .index(1)
                                .required(false)
                                .help("The input file to read the plaintext message from. You can leave blank or use the value '-' to signify STDIN."))
                )
                .subcommand(
                    SubCommand::with_name("verify")
                        .setting(AppSettings::DisableVersion)
                        .about("Verify a signature using the signing identity's public key. This requires having the signing identity imported.")
                        .arg(Arg::with_name("SIGNATURE")
                                .index(1)
                                .required(true)
                                .help("The input file to read the signature from. If the signature is deattached, you will also need to spcify the MESSAGE argument. You can leave blank or use the value '-' to signify STDIN."))
                        .arg(Arg::with_name("MESSAGE")
                                .index(2)
                                .required(false)
                                .help("The input file to read the plaintext message from. You can leave blank or use the value '-' to signify STDIN."))
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
                        .arg(id_arg("The ID of the identity we want to re-sign. This overrides the configured default identity."))
                )
                .subcommand(
                    SubCommand::with_name("resave")
                        .setting(AppSettings::DisableVersion)
                        .about("Load an identity from the database and save it again. Useful for dealing with database changes.")
                        .arg(id_arg("The ID of the identity we want to re-save. This overrides the configured default identity."))
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
                        ("photo", Some(args)) => {
                            let id = id_val(args)?;
                            let private = args.is_present("private");
                            let photo = args.value_of("PHOTO")
                                .ok_or(format!("Must specify a photo"))?;
                            commands::claim::new_photo(&id, photo, private)?;
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
                ("req", Some(args)) => {
                    drop(args);
                    unimplemented!();
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
                    unimplemented!();
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
                    let keyfile = args.value_of("keyfile");
                    let keyparts: Vec<&str> = match args.values_of("KEYPARTS") {
                        Some(iter) => iter.collect(),
                        None => vec![],
                    };
                    commands::keychain::passwd(&id, keyfile, keyparts)?;
                }
                ("keyfile", Some(args)) => {
                    let id = id_val(args)?;
                    let shamir = args.value_of("shamir").unwrap_or("1/1");
                    let output = args.value_of("output").unwrap_or("-");
                    commands::keychain::keyfile(&id, shamir, output)?;
                }
                _ => println!("{}", args.usage()),
            }
        }
        ("message", Some(args)) => {
            match args.subcommand() {
                ("send", Some(args)) => {
                    let from_id = id_val(args)?;
                    let key_from_search = args.value_of("key-from");
                    let key_to_search = args.value_of("key-to");
                    let output = args.value_of("output").unwrap_or("-");
                    let search = args.value_of("SEARCH")
                        .ok_or(format!("Must specify a search value"))?;
                    let input = args.value_of("MESSAGE").unwrap_or("-");
                    let base64 = args.is_present("base64");
                    commands::message::send(&from_id, key_from_search, key_to_search, input, output, search, base64)?;
                }
                ("send-anonymous", Some(args)) => {
                    let key_to_search = args.value_of("key-to");
                    let output = args.value_of("output").unwrap_or("-");
                    let search = args.value_of("SEARCH")
                        .ok_or(format!("Must specify a search value"))?;
                    let input = args.value_of("MESSAGE").unwrap_or("-");
                    let base64 = args.is_present("base64");
                    commands::message::send_anonymous(key_to_search, input, output, search, base64)?;
                }
                ("open", Some(args)) => {
                    let to_id = id_val(args)?;
                    let key_open = args.value_of("key-open");
                    let output = args.value_of("output").unwrap_or("-");
                    let input = args.value_of("ENCRYPTED").unwrap_or("-");
                    commands::message::open(&to_id, key_open, input, output)?;
                }
                _ => println!("{}", args.usage()),
            }
        }
        ("signature", Some(args)) => {
            match args.subcommand() {
                ("sign", Some(args)) => {
                    let sign_id = id_val(args)?;
                    let key_sign_search = args.value_of("key-sign");
                    let output = args.value_of("output").unwrap_or("-");
                    let input = args.value_of("MESSAGE").unwrap_or("-");
                    let attached = args.is_present("attached");
                    let base64 = args.is_present("base64");
                    commands::sign::sign(&sign_id, key_sign_search, input, output, attached, base64)?;
                }
                ("verify", Some(args)) => {
                    let signature = args.value_of("SIGNATURE").unwrap_or("-");
                    let input = args.value_of("MESSAGE");
                    commands::sign::verify(signature, input)?;
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

