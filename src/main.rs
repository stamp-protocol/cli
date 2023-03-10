#[macro_use] extern crate prettytable;
#[macro_use] mod util;
mod commands;
mod config;
mod db;
mod log;

use clap::{
    builder::{Command, TypedValueParser},
    Arg, ArgAction, ArgGroup, ArgMatches,
};
use stamp_core::{
    identity::{
        IdentityID,
        RelationshipType,
    },
};
use stamp_net::{Multiaddr};
use std::convert::TryFrom;
use std::ffi::OsStr;
use std::str::FromStr;

#[derive(Debug, Clone)]
struct MultiaddrParser {}
impl MultiaddrParser {
    fn new() -> Self { Self {} }
}

impl TypedValueParser for MultiaddrParser {
    type Value = Multiaddr;

    fn parse_ref(&self, _cmd: &Command, _arg: Option<&Arg>, value: &OsStr) -> Result<Self::Value, clap::error::Error> {
        let converted = value.to_string_lossy();
        Self::Value::from_str(&converted).map_err(|e| clap::Error::raw(clap::error::ErrorKind::InvalidValue, e))
    }
}

/// A private syncing token. Has the channel value (always required) and an
/// optional shared key, which can be used to decrypt the resulting messages.
/// Without the shared key, a node can only store and regurgitate encrypted
/// messages in the channel. This in itself is useful for running a listener
/// on public systems (the "cLoUd!")
#[derive(Debug, Clone)]
pub struct SyncToken {
    pub identity_id: String,
    pub channel: String,
    pub shared_key: Option<String>,
}
impl SyncToken {
    /// Create a new `SyncToken`
    pub fn new(identity_id: String, channel: String, shared_key: Option<String>) -> Self {
        Self { identity_id, channel, shared_key }
    }
}

#[derive(Debug, Clone)]
struct SyncTokenParser {}
impl SyncTokenParser {
    fn new() -> Self { Self {} }
}

impl TypedValueParser for SyncTokenParser {
    type Value = SyncToken;

    fn parse_ref(&self, _cmd: &Command, _arg: Option<&Arg>, value: &OsStr) -> Result<Self::Value, clap::error::Error> {
        let converted = value.to_string_lossy();
        let parts = converted.split(':').collect::<Vec<_>>();
        let identity_id = parts.get(0)
            .ok_or(clap::Error::raw(clap::error::ErrorKind::InvalidValue, "Invalid token given"))?;
        let channel = parts.get(1)
            .ok_or(clap::Error::raw(clap::error::ErrorKind::InvalidValue, "Invalid token given"))?;
        let shared_key = parts.get(2).map(|x| String::from(*x));
        Ok(Self::Value::new(String::from(*identity_id), String::from(*channel), shared_key))
    }
}

fn run() -> Result<(), String> {
    let conf = config::load()?;
    log::init()?;
    db::ensure_schema()?;
    let id_arg = |help: &'static str| -> Arg {
        let arg = Arg::new("identity")
            .long("id")
            .num_args(1)
            .value_name("identity id")
            .help(help);
        arg
    };
    let stage_arg = || -> Arg {
        Arg::new("stage")
            .action(ArgAction::SetTrue)
            .num_args(0)
            .short('s')
            .long("stage")
            .help("Stage this transaction instead of immediately applying. This is mainly useful for group-managed identities or creating detached stamps.")
    };
    let signwith_arg = || -> Arg {
        Arg::new("admin-key")
            .short('k')
            .long("sign-with")
            .num_args(1)
            .help("Sign this transaction with a specific admin key id/name (list admin keys with `stamp keychain list --admin`).")
    };
    let claim_private_arg = || -> Arg {
        Arg::new("private")
            .action(ArgAction::SetTrue)
            .num_args(0)
            .short('p')
            .long("private")
            .help("Indicates this is a private claim. Private claims cannot be read by anyone without giving them explicit access, and are great for things like your home address or your various relationships.")
    };
    let claim_name_arg = || -> Arg {
        Arg::new("claim-name")
            .short('n')
            .long("name")
            .num_args(1)
            .help("Gives this claim a name. This is useful when you want a claim to be easily identifiable by other people or apps (ex \"primary-email\").")
    };

    let id_val = |args: &ArgMatches| -> Result<String, String> {
        args.get_one::<String>("identity")
            .map(|x| x.clone())
            .or_else(|| {
                if let Some(id_full) = conf.default_identity.as_ref() {
                    eprintln!("Selecting default identity {} (override with `--id <ID>`)\n", IdentityID::short(&id_full));
                }
                conf.default_identity.clone()
            })
            .ok_or(format!("Must specify an ID"))
    };
    let app = Command::new("Stamp")
        .version(env!("CARGO_PKG_VERSION"))
        .bin_name("stamp")
        .max_term_width(util::term_maxwidth())
        .about("A command line interface to the Stamp identity protocol.")
        .after_help("EXAMPLES:\n    stamp id new\n        Create a new identity\n    stamp id list\n        List all local identities\n    stamp keychain keyfile -s 3,5 -o ~/backup.key\n        Back up your master key into a recovery file in case you lose your master passphrase.")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .infer_subcommands(true)
        .subcommand(
            Command::new("id")
                .about("The `id` command helps with managing identities, such as creating new ones or importing identities from other people. If you're new, start here!")
                .alias("identity")
                .subcommand_required(true)
                .arg_required_else_help(true)
                .subcommand(
                    Command::new("new")
                        .about("Creates a new identity.")
                )
                .subcommand(
                    Command::new("vanity")
                        .about("Creates a new identity with a vanity ID value. In other words, instead of a random string for an ID, we attempt to generate one that satisfies the given critera. Keep in mind, vanity IDs beyond just a few characters can take a long time to find.")
                        .arg(Arg::new("regex")
                            .short('r')
                            .long("regex")
                            .num_args(1)
                            .help("A regex, ex: (?i)[-_]re{3,}[-_]"))
                        .arg(Arg::new("contains")
                            .short('c')
                            .long("contains")
                            .num_args(1)
                            .action(ArgAction::Append)
                            .help("Contains a value, ex: 123"))
                        .arg(Arg::new("prefix")
                            .short('p')
                            .long("prefix")
                            .num_args(1)
                            .help("Vanity prefix, ex: sam-"))
                        .arg(stage_arg())
                        .arg(signwith_arg())
                )
                .subcommand(
                    Command::new("list")
                        .about("List all locally stored identities (both owned and imported).")
                        .arg(Arg::new("verbose")
                            .action(ArgAction::SetTrue)
                            .short('v')
                            .long("verbose")
                            .help("Verbose output, with long-form IDs."))
                        .arg(Arg::new("SEARCH")
                            .index(1)
                            .help("A search value to look for in an identity's ID, name, and email"))
                        //.after_help("EXAMPLES:\n    stamp id list\n        List all identities\n    stamp id list -v '@AOL.com'\n        Find all identities that contain an AOL email with high verbosity\n    stamp id list x5u-2yy9vrPoo\n        Search for an identity by ID")
                )
                .subcommand(
                    Command::new("import")
                        .about("Import an identity. It can be either one of your private identities you exported or someone else's published identity that you're importing to verify a signature they made, to stamp one of their claims, send them an encrypted message, etc.")
                        .arg(Arg::new("LOCATION")
                            .required(true)
                            .index(1)
                            .help("The location of the identity we're importing. Can be a local file or a URL."))
                )
                .subcommand(
                    Command::new("publish")
                        .about("Publish one of your identities. This outputs the identity in a format others can import. For instance you can publish it to a URL you own or a social network. Requires access to the identity's publish keypair.")
                        .arg(id_arg("The ID of the identity we want to publish. This overrides the configured default identity."))
                        .arg(Arg::new("output")
                            .short('o')
                            .long("output")
                            .num_args(1)
                            .help("The output file to write to. You can leave blank or use the value '-' to signify STDOUT."))
                        .arg(stage_arg())
                        .arg(signwith_arg())
                        .group(ArgGroup::new("stage-out")
                            .args(["stage"])
                            .conflicts_with("output"))
                )
                .subcommand(
                    Command::new("export-private")
                        .about("Export one of your identities. This export includes private keys so even though it is encrypted, it's important you do not share it with *anybody*. EVER.")
                        .arg(id_arg("The ID of the identity we want to export. This overrides the configured default identity."))
                        .arg(Arg::new("output")
                            .short('o')
                            .long("output")
                            .num_args(1)
                            .help("The output file to write to. You can leave blank or use the value '-' to signify STDOUT."))
                )
                .subcommand(
                    Command::new("delete")
                        .about("Remove a locally-stored identity.")
                        .arg(Arg::new("SEARCH")
                            .required(true)
                            .index(1)
                            .help("An identity ID, name, or email to search for when deleting."))
                        .arg(Arg::new("yes")
                            .action(ArgAction::SetTrue)
                            .short('y')
                            .long("yes")
                            .help("Do not confirm deletion, just delete. Use with caution."))
                        .arg(Arg::new("verbose")
                            .action(ArgAction::SetTrue)
                            .short('v')
                            .long("verbose")
                            .help("Use verbose output with long-form IDs when printing deletion table."))
                )
                .subcommand(
                    Command::new("view")
                        .about("View a full identity in human-readable format. Not suitable for sharing, importing, etc but can be helpful to get a full picture of what your identity or someone else's looks like.")
                        .alias("print")
                        .arg(Arg::new("SEARCH")
                            .required(true)
                            .index(1)
                            .help("An identity ID, name, or email to search for when deleting."))
                )
        )
        .subcommand(
            Command::new("claim")
                .about("Allows updating and checking claims. Claims are pieces of identifying information attached to your identity that others can verify and \"stamp.\"")
                .alias("claims")
                .subcommand_required(true)
                .arg_required_else_help(true)
                .subcommand(
                    Command::new("new")
                        .about("Create a new claim that contains information anybody can view. This is good for things like your name or email.")
                        .alias("add")
                        .subcommand_required(true)
                        .arg_required_else_help(true)
                        .subcommand(
                            Command::new("identity")
                                .about("Create an identity ownership claim. This is always created automatically for any new identity you create, but can also be created for another identity (for instance if you move to a new identity).")
                                .arg(id_arg("The ID of the identity we want to add a claim to. This overrides the configured default identity."))
                                .arg(stage_arg())
                                .arg(signwith_arg())
                                .arg(claim_private_arg())
                                .arg(claim_name_arg())
                        )
                        .subcommand(
                            Command::new("name")
                                .about("Claim your full name. Generally you only have one name claim, but you are free to add more if you wish.")
                                .arg(id_arg("The ID of the identity we want to add a claim to. This overrides the configured default identity."))
                                .arg(stage_arg())
                                .arg(signwith_arg())
                                .arg(claim_private_arg())
                                .arg(claim_name_arg())
                        )
                        .subcommand(
                            Command::new("birthday")
                                .alias("dob")
                                .about("Claim your birthday/date of birth. Generally you only have one birthday claim, but you are free to add more if you wish.")
                                .arg(id_arg("The ID of the identity we want to add a claim to. This overrides the configured default identity."))
                                .arg(stage_arg())
                                .arg(signwith_arg())
                                .arg(claim_private_arg())
                                .arg(claim_name_arg())
                        )
                        .subcommand(
                            Command::new("email")
                                .about("Claim ownership of an email address.")
                                .arg(id_arg("The ID of the identity we want to add a claim to. This overrides the configured default identity."))
                                .arg(stage_arg())
                                .arg(signwith_arg())
                                .arg(claim_private_arg())
                                .arg(claim_name_arg())
                        )
                        .subcommand(
                            Command::new("photo")
                                .about("Claim that a photo is you.")
                                .arg(id_arg("The ID of the identity we want to add a claim to. This overrides the configured default identity."))
                                .arg(stage_arg())
                                .arg(signwith_arg())
                                .arg(claim_private_arg())
                                .arg(claim_name_arg())
                                .arg(Arg::new("PHOTO-FILE")
                                    .index(1)
                                    .required(true)
                                    .help("The input file to read the photo from. You can leave blank or use the value '-' to signify STDIN."))
                        )
                        .subcommand(
                            Command::new("pgp")
                                .about("Claim ownership of a PGP identity. It's probably best to use the long-form ID for this.")
                                .arg(id_arg("The ID of the identity we want to add a claim to. This overrides the configured default identity."))
                                .arg(stage_arg())
                                .arg(signwith_arg())
                                .arg(claim_private_arg())
                                .arg(claim_name_arg())
                        )
                        .subcommand(
                            Command::new("domain")
                                .about("Claim ownership of a domain. You must have access to create a TXT record on the domain. This claim can be checked by anybody using the `stamp claim check` command.")
                                .arg(id_arg("The ID of the identity we want to add a claim to. This overrides the configured default identity."))
                                .arg(stage_arg())
                                .arg(signwith_arg())
                                .arg(claim_private_arg())
                                .arg(claim_name_arg())
                        )
                        .subcommand(
                            Command::new("url")
                                .about("Claim ownership of a URL. This can be used for claiming ownership of websites or social media profiles. You must have the ability to update the content this URL points to. This claim can be checked by anybody using the `stamp claim check` command.")
                                .arg(id_arg("The ID of the identity we want to add a claim to. This overrides the configured default identity."))
                                .arg(stage_arg())
                                .arg(signwith_arg())
                                .arg(claim_private_arg())
                                .arg(claim_name_arg())
                        )
                        .subcommand(
                            Command::new("address")
                                .about("Claim a home address. (Hint: you might want the -p flag with this unless you like meeting internet strangers)")
                                .arg(id_arg("The ID of the identity we want to add a claim to. This overrides the configured default identity."))
                                .arg(stage_arg())
                                .arg(signwith_arg())
                                .arg(claim_private_arg())
                                .arg(claim_name_arg())
                        )
                        .subcommand(
                            Command::new("relation")
                                .about("Claim that you are in a relationship with another identity.")
                                .arg(id_arg("The ID of the identity we want to add a claim to. This overrides the configured default identity."))
                                .arg(stage_arg())
                                .arg(signwith_arg())
                                .arg(Arg::new("TYPE")
                                    .required(true)
                                    .index(1)
                                    .value_parser(clap::builder::PossibleValuesParser::new(["org"]))
                                    .help("The relationship type."))
                                .arg(claim_private_arg())
                                .arg(claim_name_arg())
                        )
                )
                .subcommand(
                    Command::new("check")
                        .about("This command verifies domain and URL claims immediately. This lets us prove ownership of domains, websites, and social media profiles in a distributed fashion without requiring third-party verification. Bye, Keybase.")
                        .arg(Arg::new("CLAIM")
                            .required(true)
                            .index(1)
                            .help("The ID of the claim we're checking. Must be a public `Domain` or `URL` claim. The identity owning the claim must be imported locally."))
                )
                .subcommand(
                    Command::new("view")
                        .about("View the data in a claim. If the claim is private, you will be prompted for your master password. If the claim is not owned by you, an error is thrown.")
                        .arg(id_arg("The ID of the identity we are viewing the claim for. This overrides the configured default identity."))
                        .arg(Arg::new("output")
                            .short('o')
                            .long("output")
                            .num_args(1)
                            .help("The output file to write to. You can leave blank or use the value '-' to signify STDOUT."))
                        .arg(Arg::new("CLAIM")
                            .required(true)
                            .index(1)
                            // you gandered, sir.
                            .help("The ID of the claim we're gandering."))
                )
                .subcommand(
                    Command::new("list")
                        .about("List the claims on an identity.")
                        .arg(id_arg("The ID of the identity we are listing the claims for. This overrides the configured default identity."))
                        .arg(Arg::new("private")
                            .action(ArgAction::SetTrue)
                            .short('p')
                            .long("private")
                            .help("Indicates this is a private claim. Private claims cannot be read by anyone without giving them explicit access, and are great for things like your home address or your various relationships."))
                        .arg(Arg::new("verbose")
                            .action(ArgAction::SetTrue)
                            .short('v')
                            .long("verbose")
                            .help("Verbose output, with long-form IDs."))
                )
                .subcommand(
                    Command::new("delete")
                        .about("Remove a claim from your identity.")
                        .arg(id_arg("The ID of the identity we are removing the claim from. This overrides the configured default identity."))
                        .arg(stage_arg())
                        .arg(signwith_arg())
                        .arg(Arg::new("CLAIM")
                            .required(true)
                            .index(1)
                            .help("The ID of the claim we're deleting."))
                )
        )
        .subcommand(
            Command::new("stamp")
                .about("Create or revoke stamps on the claims of other identities. Stamps form a network of trust for the identity system: stamps from people or institutions you trust transfer that trust onto others.")
                .alias("stamps")
                .subcommand_required(true)
                .arg_required_else_help(true)
                .subcommand(
                    Command::new("new")
                        .alias("stamp")
                        .about("Stamp a claim. This is a signal of trust between one identity and another. Stamps can be made public by saving them to your identity (which happens by default), or they can be detached using the `-s` flag.")
                        .arg(id_arg("The ID of the identity we are stamping from. This overrides the configured default identity."))
                        .arg(Arg::new("CLAIM")
                            .index(1)
                            .required(true)
                            .help("The ID (prefix or full) of the claim we wish to stamp."))
                        .arg(Arg::new("output")
                            .short('o')
                            .long("output")
                            .num_args(1)
                            .help("The output file to write to. You can leave blank or use the value '-' to signify STDOUT."))
                        .arg(stage_arg())
                        .arg(signwith_arg())
                )
                .subcommand(
                    Command::new("req")
                        .about("Create a stamp request. This is is generally needed when you want to have another identity stamp a private claim, in which case the claim is decrypted with your master key, then encrypted via the recipient's public key so only they can open it. You can also send stamp requests for public claims as well.")
                        .arg(Arg::new("key-from")
                            .short('f')
                            .long("key-from")
                            .num_args(1)
                            .help("The ID or name of the `crypto` key in your keychain you want to sign the message with. If you don't specify this, you will be prompted."))
                        .arg(Arg::new("key-to")
                            .short('t')
                            .long("key-to")
                            .num_args(1)
                            .help("The ID or name of the `crypto` key in the recipient's keychain that the message will be encrypted with. If you don't specify this, you will be prompted. The recipient's identity must be stored locally."))
                        .arg(Arg::new("output")
                            .short('o')
                            .long("output")
                            .num_args(1)
                            .help("The output file to write the encrypted message to. You can leave blank or use the value '-' to signify STDOUT."))
                        .arg(Arg::new("base64")
                            .action(ArgAction::SetTrue)
                            .short('b')
                            .long("base64")
                            .help("If set, output the encrypted message as base64 (which is easier to put in email or a website),"))
                        .arg(id_arg("The ID of the identity we are creating the stamp request for. This overrides the configured default identity."))
                        .arg(Arg::new("CLAIM")
                            .index(1)
                            .required(true)
                            .help("The ID of the claim we want to request a stamp on."))
                )
                .subcommand(
                    Command::new("list")
                        .about("List all public stamps we have made. To view stamps others have made, see the `stamp claim stamps` command.")
                        .arg(Arg::new("verbose")
                            .action(ArgAction::SetTrue)
                            .short('v')
                            .long("verbose")
                            .help("Verbose output, with long-form IDs."))
                )
                .subcommand(
                    Command::new("accept")
                        .about("Accept a stamp someone else has made on one of our claims.")
                        .arg(id_arg("The ID of the identity we are accepting the stamp for. This overrides the configured default identity."))
                        .arg(Arg::new("LOCATION")
                            .required(true)
                            .index(1)
                            .help("The stamp we're accepting, generally a file."))
                        .arg(stage_arg())
                        .arg(signwith_arg())
                )
                .subcommand(
                    Command::new("revoke")
                        .about("Revoke a stamp we've made on another identity. Note that the stamp must be present on an identity that's stored locally.")
                        .arg(Arg::new("STAMP")
                            .required(true)
                            .index(1)
                            .help("The ID of the stamp we're revoking."))
                        .arg(Arg::new("yes")
                            .action(ArgAction::SetTrue)
                            .short('y')
                            .long("yes")
                            .help("Set if you do not want to confirm the revocation."))
                        .arg(stage_arg())
                        .arg(signwith_arg())
                )
        )
        .subcommand(
            Command::new("keychain")
                .about("Allows managing the keys in an identity's keychain. This includes changing the master passphrase for the identity, and generating or revoking subkeys.")
                .subcommand_required(true)
                .arg_required_else_help(true)
                .subcommand(
                    Command::new("new")
                        .about("Create a new key and add it to your keychain.")
                        .alias("add")
                        .subcommand_required(true)
                        .arg_required_else_help(true)
                        .subcommand(
                            Command::new("admin")
                                .about("Create an admin key. Admin keys, along with policies, are used to manage the identity itself.")
                                .arg(id_arg("The ID of the identity we want to add a key to. This overrides the configured default identity."))
                                .arg(Arg::new("NAME")
                                    .required(true)
                                    .num_args(1)
                                    .index(1)
                                    .help("This key's name. The name is public and allows for organization and referencing the key by a memorable value. Ex: turtl:master-key"))
                                .arg(Arg::new("description")
                                    .short('d')
                                    .long("desc")
                                    .num_args(1)
                                    .help("They key's description, ex: Use this key to send me emails."))
                                .arg(stage_arg())
                                .arg(signwith_arg())
                        )
                        .subcommand(
                            Command::new("sign")
                                .about("Create a signing keypair. This includes a public key and a secret key. The secret key is used to create signatures on documents or messages that allow verifying (with your public key) the message was signed by you and has not been tampered with.")
                                .arg(id_arg("The ID of the identity we want to add a key to. This overrides the configured default identity."))
                                .arg(Arg::new("NAME")
                                    .required(true)
                                    .num_args(1)
                                    .index(1)
                                    .help("This key's name. The name is public and allows for organization and referencing the key by a memorable value. Ex: turtl:master-key"))
                                .arg(Arg::new("description")
                                    .short('d')
                                    .long("desc")
                                    .num_args(1)
                                    .help("They key's description, ex: Use this key to send me emails."))
                                .arg(stage_arg())
                                .arg(signwith_arg())
                        )
                        .subcommand(
                            Command::new("crypto")
                                .about("Create a crypto keypair. This includes a public key and a secret key. The public key allows others to encrypt a message which can then only be decrypted with your secret key.")
                                .arg(id_arg("The ID of the identity we want to add a key to. This overrides the configured default identity."))
                                .arg(Arg::new("NAME")
                                    .required(true)
                                    .num_args(1)
                                    .index(1)
                                    .help("This key's name. The name is public and allows for organization and referencing the key by a memorable value. Ex: turtl:master-key"))
                                .arg(Arg::new("description")
                                    .short('d')
                                    .long("desc")
                                    .num_args(1)
                                    .help("They key's description, ex: Use this key to send me emails."))
                                .arg(stage_arg())
                                .arg(signwith_arg())
                        )
                        .subcommand(
                            Command::new("secret")
                                .about("Create a secret key. Secret keys are used for encrypted and decrypting files or messages for your own personal privacy. Nobody can read your encrypted data unless they have your secret key.")
                                .arg(id_arg("The ID of the identity we want to add a key to. This overrides the configured default identity."))
                                .arg(Arg::new("NAME")
                                    .required(true)
                                    .num_args(1)
                                    .index(1)
                                    .help("This key's name. The name is public and allows for organization and referencing the key by a memorable value. Ex: turtl:master-key"))
                                .arg(Arg::new("description")
                                    .short('d')
                                    .long("desc")
                                    .num_args(1)
                                    .help("They key's description, ex: Use this key to send me emails."))
                                .arg(stage_arg())
                                .arg(signwith_arg())
                        )
                )
                .subcommand(
                    Command::new("list")
                        .about("List the keys in a keychain.")
                        .arg(Arg::new("type")
                            .short('t')
                            .long("type")
                            .num_args(1)
                            .value_parser(clap::builder::PossibleValuesParser::new(["admin", "subkey", "sign", "crypto", "secret"]))
                            .help("The type of key to list (defaults to all keys)."))
                        .arg(Arg::new("revoked")
                            .short('r')
                            .long("revoked")
                            .action(ArgAction::SetTrue)
                            .help("List revoked keys."))
                        .arg(id_arg("The ID of the identity we want to list keys for. This overrides the configured default identity."))
                        .arg(Arg::new("SEARCH")
                            .index(1)
                            .help("The ID or name of the key(s) we're searching for."))
                )
                .subcommand(
                    Command::new("update")
                        .about("Change a keys's name/description.")
                        .arg(id_arg("The ID of the identity which has the key we are updating. This overrides the configured default identity."))
                        .arg(Arg::new("name")
                            .short('n')
                            .long("name")
                            .num_args(1)
                            .help("Set the new name of this key."))
                        .arg(Arg::new("description")
                            .short('d')
                            .long("desc")
                            .num_args(1)
                            .help("Set the new description of this key."))
                        .arg(stage_arg())
                        .arg(signwith_arg())
                        .arg(Arg::new("SEARCH")
                            .required(true)
                            .index(1)
                            .help("The ID or name of the key(s) we're updating."))
                )
                .subcommand(
                    Command::new("revoke")
                        .about("Revoke a key in your keychain. This can be either an admin key or a subkey. It's a good idea to revoke all keys for some time before using `delete` with the exception of secret keys.")
                        .arg(Arg::new("reason")
                            .short('r')
                            .long("reason")
                            .num_args(1)
                            .value_parser(clap::builder::PossibleValuesParser::new(["unspecified", "superseded", "compromised", "invalid"]))
                            .help("The reason you're revoking this key (defaults to \"unspecified\")"))
                        .arg(id_arg("The ID of the identity we want to revoke a key of. This overrides the configured default identity."))
                        .arg(stage_arg())
                        .arg(signwith_arg())
                        .arg(Arg::new("SEARCH")
                            .index(1)
                            .help("The ID or name of the key(s) we're searching for."))
                )
                .subcommand(
                    Command::new("delete-subkey")
                        .about("Delete a subkey from your keychain. This does not work on admin keys (they must be revoked before deletion). Generally, you'll want to only use `delete` for secret key types. If you're deleting a signing or crypto key, you really might want the `revoke` command instead.")
                        .arg(id_arg("The ID of the identity we want to delete keys from. This overrides the configured default identity."))
                        .arg(stage_arg())
                        .arg(signwith_arg())
                        .arg(Arg::new("SEARCH")
                            .required(true)
                            .index(1)
                            .help("The ID or name of the key(s) we're searching for."))
                )
                .subcommand(
                    Command::new("passwd")
                        .about("Change the master passphrase for the private keys in an identity.")
                        .arg(Arg::new("keyfile")
                            .short('k')
                            .long("keyfile")
                            .num_args(1)
                            .help("If you generated a keyfile via `stamp keychain keyfile` you can pass it here. This lets you recover your identity even if you lost your master passphrase."))
                        .arg(Arg::new("KEYPARTS")
                            .index(1)
                            .num_args(1..)
                            .required(false)
                            .help("If instead of a keyfile you have individual parts of your master key (generated with `stamp keychain keyfile`), you can enter them here as separate arguments to recover your identity even if you lost your master passphrase."))
                        // off in whose camper they were whacking
                        .arg(id_arg("The ID of the identity we want to change the master passphrase for. This overrides the configured default identity."))
                )
                .subcommand(
                    Command::new("keyfile")
                        .about("Back up your master key such that it can be used with the `stamp keychain passwd` command to recover your identity in the event you lose your master passphrase. This command has the ability to use Shamir's algorithm so you can split your master key into multiple parts, each of which can be saved to different location (or given to different people). Later, you can recover your master key if you have some minimum number of these parts. If you elect to use Shamir's, each key part will be output on its own line.")
                        .arg(Arg::new("shamir")
                            .short('s')
                            .long("shamir")
                            .num_args(1)
                            .help("A value in the format M/S (eg 3/5) that splits the key into S parts and requires at least M parts to recover the key (Default: 1/1)"))
                        .arg(Arg::new("output")
                            .short('o')
                            .long("output")
                            .num_args(1)
                            .help("The output file to write to. You can leave blank or use the value '-' to signify STDOUT."))
                        .arg(id_arg("The ID of the identity we want to backup the master key for. This overrides the configured default identity."))
                )
        )
        .subcommand(
            Command::new("policy")
                .about("Allows assigning various capabilities to different combinations of admin keys, making it possible for only certain keys to be able to perform various tasks or even for admin keys from other identities to manage this identity: group identities.")
                .alias("pol")
                .subcommand_required(true)
                .arg_required_else_help(true)
                .subcommand(
                    // TODO
                    Command::new("create")
                        .about("Creates a new policy.")
                )
        )
        .subcommand(
            Command::new("message")
                .about("Allows sending and receiving encrypted messages between identities.")
                .alias("msg")
                .subcommand_required(true)
                .arg_required_else_help(true)
                .subcommand(
                    Command::new("send")
                        .about("Send a message to another identity. This message will be signed with a `crypto` key of your choosing (in your keychain) which will allow the recipient to verify that the message is in fact from you.")
                        .arg(Arg::new("key-from")
                            .short('f')
                            .long("key-from")
                            .num_args(1)
                            .help("The ID or name of the `crypto` key in your keychain you want to sign the message with. If you don't specify this, you will be prompted."))
                        .arg(Arg::new("key-to")
                            .short('t')
                            .long("key-to")
                            .num_args(1)
                            .help("The ID or name of the `crypto` key in the recipient's keychain that the message will be encrypted with. If you don't specify this, you will be prompted."))
                        .arg(Arg::new("output")
                            .short('o')
                            .long("output")
                            .num_args(1)
                            .help("The output file to write the encrypted message to. You can leave blank or use the value '-' to signify STDOUT."))
                        .arg(Arg::new("base64")
                            .action(ArgAction::SetTrue)
                            .short('b')
                            .long("base64")
                            .help("If set, output the encrypted message as base64 (which is easier to put in email or a website),"))
                        .arg(id_arg("The ID of the identity we want to send from. This overrides the configured default identity."))
                        .arg(Arg::new("SEARCH")
                            .index(1)
                            .required(true)
                            .help("Look for the recipient by identity ID, email, or name"))
                        .arg(Arg::new("MESSAGE")
                            .index(2)
                            .required(false)
                            .help("The input file to read the plaintext message from. You can leave blank or use the value '-' to signify STDIN."))
                )
                .subcommand(
                    Command::new("send-anonymous")
                        .about("Send an anonymous message to another identity. This message is not signed by any of your keys, which means the recipient doesn't need to have your identity on hand to open the message.")
                        .arg(Arg::new("key-to")
                            .short('t')
                            .long("key-to")
                            .num_args(1)
                            .help("The ID or name of the `crypto` key in the recipient's keychain that the message will be encrypted with. If you don't specify this, you will be prompted."))
                        .arg(Arg::new("output")
                            .short('o')
                            .long("output")
                            .num_args(1)
                            .help("The output file to write the encrypted message to. You can leave blank or use the value '-' to signify STDOUT."))
                        .arg(Arg::new("base64")
                            .action(ArgAction::SetTrue)
                            .short('b')
                            .long("base64")
                            .help("If set, output the encrypted message as base64 (which is easier to put in email or a website),"))
                        .arg(Arg::new("SEARCH")
                            .index(1)
                            .required(true)
                            .help("Look for the recipient by identity ID, email, or name"))
                        .arg(Arg::new("MESSAGE")
                            .index(2)
                            .required(false)
                            .help("The input file to read the plaintext message from. You can leave blank or use the value '-' to signify STDIN."))
                )
                .subcommand(
                    Command::new("open")
                        .about("Open a message from another identity. This can be either a signed message or anonymous, although if the message is signed then the sender's identity must be imported.")
                        .arg(Arg::new("key-open")
                            .short('k')
                            .long("key-open")
                            .num_args(1)
                            .help("The ID or name of the `crypto` key in your keychain that the message will be opened with. If you don't specify this, you will be prompted."))
                        .arg(Arg::new("output")
                            .short('o')
                            .long("output")
                            .num_args(1)
                            .help("The output file to write the plaintext message to. You can leave blank or use the value '-' to signify STDOUT."))
                        .arg(id_arg("The ID of the identity the message was sent to. This overrides the configured default identity."))
                        .arg(Arg::new("ENCRYPTED")
                            .index(1)
                            .required(false)
                            .help("The input file to read the encrypted message from. You can leave blank or use the value '-' to signify STDIN."))
                )
        )
        .subcommand(
            Command::new("sign")
                .about("Sign and verify messages and documents")
                .alias("signature")
                .alias("sig")
                .subcommand_required(true)
                .arg_required_else_help(true)
                .subcommand(
                    Command::new("sign")
                        .about("Sign a message or document with one of your `sign` keys. This signature can only be created with your private signing key, but anybody who has your public key can verify the message is unaltered.")
                        .arg(Arg::new("key-sign")
                            .short('k')
                            .long("key-sign")
                            .num_args(1)
                            .help("The ID or name of the `sign` key you wish to sign with. If you don't specify this, you will be prompted."))
                        .arg(Arg::new("output")
                            .short('o')
                            .long("output")
                            .num_args(1)
                            .help("The output file to write the signature to. You can leave blank or use the value '-' to signify STDOUT."))
                        .arg(Arg::new("attached")
                            .action(ArgAction::SetTrue)
                            .short('a')
                            .long("attached")
                            .help("If set, the message body will be appended to the signature. This allows you to send a message and the signature of that message together. The default is to generate a detached signature that must be published alongside the message."))
                        .arg(Arg::new("base64")
                            .action(ArgAction::SetTrue)
                            .short('b')
                            .long("base64")
                            .help("If set, output the signature as base64 (which is easier to put in email or a website),"))
                        .arg(id_arg("The ID of the identity we want to sign from. This overrides the configured default identity."))
                        .arg(Arg::new("MESSAGE")
                            .index(1)
                            .required(false)
                            .help("The input file to read the plaintext message from. You can leave blank or use the value '-' to signify STDIN."))
                )
                .subcommand(
                    Command::new("verify")
                        .about("Verify a signature using the signing identity's public key. This requires having the signing identity imported.")
                        .arg(Arg::new("SIGNATURE")
                            .index(1)
                            .required(true)
                            .help("The input file to read the signature from. If the signature is deattached, you will also need to spcify the MESSAGE argument. You can leave blank or use the value '-' to signify STDIN."))
                        .arg(Arg::new("MESSAGE")
                            .index(2)
                            .required(false)
                            .help("The input file to read the plaintext message from. You can leave blank or use the value '-' to signify STDIN."))
                )
        )
        .subcommand(
            Command::new("config")
                .about("Allows manipulation of the local configuration.")
                .subcommand_required(true)
                .arg_required_else_help(true)
                .subcommand(
                    Command::new("set-default")
                        .about("Set the default identity ID used for many of the other commands")
                        .arg(Arg::new("SEARCH")
                            .required(true)
                            .index(1)
                            .help("An identity ID, name, or email to search for when deleting."))
                )
        )
        .subcommand(
            Command::new("stage")
                .about("Interact with staged transactions (transactions that require multiple signatures).")
                .subcommand_required(true)
                .arg_required_else_help(true)
                .subcommand(
                    Command::new("list")
                        .about("List the staged transactions for an identity.")
                        .arg(id_arg("The ID of the identity we want to see staged transactions for. This overrides the configured default identity."))
                )
                .subcommand(
                    Command::new("view")
                        .about("View a staged transaction.")
                        .arg(Arg::new("TXID")
                            .index(1)
                            .num_args(1)
                            .required(true)
                            .help("The transaction ID you wish to view."))
                )
                .subcommand(
                    Command::new("delete")
                        .about("Delete a staged transaction without applying it to the identity.")
                        .alias("rm")
                        .alias("del")
                        .arg(Arg::new("TXID")
                            .index(1)
                            .num_args(1)
                            .required(true)
                            .help("The transaction ID you wish to view."))
                )
                .subcommand(
                    Command::new("sign")
                        .about("Sign a staged transaction with one of our keys.")
                        .arg(signwith_arg())
                        .arg(Arg::new("TXID")
                            .index(1)
                            .num_args(1)
                            .required(true)
                            .help("The transaction ID you wish to sign."))
                )
                .subcommand(
                    Command::new("apply")
                        .about("Apply a staged transaction that has a valid set of signatures to its identity. If successful, the transaction will be removed from staging.")
                        .alias("commit")
                        .arg(Arg::new("TXID")
                            .index(1)
                            .num_args(1)
                            .required(true)
                            .help("The transaction ID you wish to apply."))
                )
        )
        .subcommand(
            Command::new("sync")
                .about("Sync your private identity between your devices.")
                .subcommand_required(true)
                .arg_required_else_help(true)
                .after_help("EXAMPLE:\n    # run this on the device that has your full identity\n    stamp sync token -b\n        Your token is: TQzq9RCLXhcNqoqD\n    # run this on a home or public server\n    stamp sync listen TQzq9RCLXhcNqoqD\n        Listening on 44.55.66.77:5757\n    # run this on the device you ran `stamp sync token` on\n    stamp sync run --join 44.55.66.77:5757\n        Syncing!")
                .subcommand(
                    Command::new("listen")
                        .about("Start a long-lived private syncing peer that your devices can talk to.")
                        .arg(Arg::new("TOKEN")
                            .index(1)
                            .num_args(1)
                            .required(true)
                            .value_parser(SyncTokenParser::new())
                            .help("The token you got from running `stamp sync token -b`"))
                        .arg(Arg::new("bind")
                            .short('b')
                            .long("bind")
                            .value_name("/ip4/1.2.3.4/tcp/5757")
                            .default_value("/ip4/0.0.0.0/tcp/5757")
                            .num_args(1)
                            .value_parser(MultiaddrParser::new())
                            .help("The address to listen on"))
                        .arg(Arg::new("join")
                            .action(ArgAction::Append)
                            .short('j')
                            .long("join")
                            .num_args(1)
                            .value_parser(MultiaddrParser::new())
                            .value_name("/dns/boot1.stampnet.org/tcp/5757")
                            .help("Join an existing node. This can be a node you own, or a public relay which allows secure communication between your personal nodes even behind firewalls. Can be specified multiple times."))
                )
                .subcommand(
                    Command::new("run")
                        .about("Runs the private sync. On the first run, you will have to specify a listener via --join, but afterwards the listener(s) will be saved and you can omit the --join option.")
                        .arg(id_arg("The ID of the identity we are syncing. This overrides the configured default identity."))
                        .arg(Arg::new("TOKEN")
                            .index(1)
                            .value_parser(SyncTokenParser::new())
                            .help("The full syncing token you got from running `stamp sync token`. Only needs to be specified once per identity."))
                        .arg(Arg::new("join")
                            .action(ArgAction::Append)
                            .short('j')
                            .long("join")
                            .num_args(1)
                            .value_parser(MultiaddrParser::new())
                            .value_name("/dns/boot1.stampnet.org/tcp/5757")
                            .help("Join an existing node. This can be a node you own, or a public relay which allows secure communication between your personal nodes even behind firewalls."))
                )
                .subcommand(
                    Command::new("token")
                        .about("Create and display the token used for private syncing.") 
                        .arg(id_arg("The ID of the identity we want to set up syncing for. This overrides the configured default identity."))
                        .arg(Arg::new("regen")
                            .short('r')
                            .long("regen")
                            .num_args(0)
                            .help("Use to regenerate your token. Helpful if the original is compromised or lost."))
                        .arg(Arg::new("blind")
                            .action(ArgAction::SetTrue)
                            .short('b')
                            .long("blind")
                            .num_args(0)
                            .help("Used when initiating a \"blind\" (non-decrypting) peer/device. Useful for peers on public networks/cloud services."))
                )
        )
        .subcommand(
            Command::new("dag")
                .about("Interact with an identity's DAG directly.")
                .subcommand_required(true)
                .arg_required_else_help(true)
                .subcommand(
                    Command::new("list")
                        .about("List the transactions in an identity.")
                        .arg(id_arg("The ID of the identity we want to see transactions for. This overrides the configured default identity."))
                )
                .subcommand(
                    Command::new("reset")
                        .about("Roll back an identity to a previous state.")
                        .arg(id_arg("The ID of the identity we want to reset. This overrides the configured default identity."))
                        .arg(Arg::new("TXID")
                            .required(true)
                            .index(1)
                            .help("A transaction ID we wish to reset to. This transaction will be included in the final identity."))
                )
        )
        .subcommand(
            Command::new("debug")
                .about("Tools for Stamp development. Will change rapidly and unexpectedly, so don't rely on these too heavily.")
                .subcommand_required(true)
                .arg_required_else_help(true)
                .subcommand(
                    Command::new("resave")
                        .about("Load an identity from the database and save it again. Useful for dealing with database changes.")
                        .arg(id_arg("The ID of the identity we want to re-save. This must be specified."))
                )
        );
    let args = app.get_matches();
    match args.subcommand() {
        Some(("id", args)) => {
            match args.subcommand() {
                Some(("new", _)) => {
                    crate::commands::id::passphrase_note();
                    let (transactions, master_key) = util::with_new_passphrase("Your master passphrase", |master_key, now| {
                        stamp_aux::id::create_personal_random(&master_key, now)
                            .map_err(|e| format!("Error creating identity: {}", e))
                    }, None)?;
                    println!("");
                    let identity = transactions.build_identity()
                        .map_err(|err| format!("Failed to build identity: {:?}", err))?;
                    let id_str = id_str!(identity.id())?;
                    println!("Generated a new identity with the ID {}", id_str);
                    println!("");
                    let (name, email) = crate::commands::id::prompt_name_email()?;
                    let transactions = stamp_aux::id::post_new_personal_id(&master_key, transactions, name, email)
                        .map_err(|e| format!("Error finalizing identity: {}", e))?;
                    crate::commands::id::post_create(&transactions)?;
                }
                Some(("vanity", args)) => {
                    let regex = args.get_one::<String>("regex").map(|x| x.as_str());
                    let contains: Vec<&str> = args.get_many::<String>("contains")
                        .unwrap_or_default()
                        .map(|v| v.as_str())
                        .collect();
                    let prefix = args.get_one::<String>("prefix").map(|x| x.as_str());
                    if regex.is_none() && contains.len() == 0 && prefix.is_none() {
                        println!("Please specify --regex, --contains, or --prefix");
                        return Ok(());
                    }

                    let (tmp_master_key, transactions, now) = commands::id::create_vanity(regex, contains, prefix)?;
                    crate::commands::id::passphrase_note();
                    let (_, master_key) = util::with_new_passphrase("Your master passphrase", |_master_key, _now| { Ok(()) }, Some(now.clone()))?;
                    let transactions = transactions.reencrypt(&tmp_master_key, &master_key)
                        .map_err(|err| format!("Failed to create identity: {}", err))?;
                    let (name, email) = crate::commands::id::prompt_name_email()?;
                    let transactions = stamp_aux::id::post_new_personal_id(&master_key, transactions, name, email)
                        .map_err(|e| format!("Error finalizing identity: {}", e))?;
                    crate::commands::id::post_create(&transactions)?;
                }
                Some(("list", args)) => {
                    let search = args.get_one::<String>("SEARCH").map(|x| x.as_str());
                    let verbose = args.get_flag("verbose");

                    let identities = db::list_local_identities(search)?
                        .iter()
                        .map(|x| util::build_identity(&x))
                        .collect::<Result<Vec<_>, String>>()?;
                    crate::commands::id::print_identities_table(&identities, verbose);
                }
                Some(("import", args)) => {
                    let location = args.get_one::<String>("LOCATION")
                        .map(|x| x.as_str())
                        .ok_or(format!("Must specify a location value"))?;

                    let contents = util::load_file(location)?;
                    let (transactions, existing) = stamp_aux::id::import_pre(contents.as_slice())
                        .map_err(|e| format!("Error importing identity: {}", e))?;
                    let identity = util::build_identity(&transactions)?;
                    if existing.is_some() {
                        if !util::yesno_prompt("The identity you're importing already exists locally. Overwrite? [y/N]", "n")? {
                            return Ok(());
                        }
                    }
                    let id_str = id_str!(identity.id())?;
                    db::save_identity(transactions)?;
                    println!("Imported identity {}", id_str);
                }
                Some(("publish", args)) => {
                    let id = id_val(args)?;
                    let stage = args.get_flag("stage");
                    let sign_with = args.get_one::<String>("admin-key").map(|x| x.as_str());
                    let output = args.get_one::<String>("output")
                        .map(|x| x.as_str())
                        .unwrap_or("-");
                    let published = commands::id::publish(&id, stage, sign_with)?;
                    if stage {
                        println!("Publish transaction staged! To view:\n  stamp stage view {}", published);
                    } else {
                        util::write_file(output, published.as_bytes())?;
                    }
                }
                Some(("export-private", args)) => {
                    let id = id_val(args)?;
                    let output = args.get_one::<String>("output")
                        .map(|x| x.as_str())
                        .unwrap_or("-");
                    let serialized = commands::id::export_private(&id)?;
                    util::write_file(output, serialized.as_slice())?;
                }
                Some(("delete", args)) => {
                    let search = args.get_one::<String>("SEARCH")
                        .map(|x| x.as_str())
                        .ok_or(format!("Must specify a search value"))?;
                    let skip_confirm = args.get_flag("yes");
                    let verbose = args.get_flag("verbose");
                    commands::id::delete(search, skip_confirm, verbose)?
                }
                Some(("view", args)) => {
                    let search = args.get_one::<String>("SEARCH")
                        .map(|x| x.as_str())
                        .ok_or(format!("Must specify a search value"))?;
                    let identity = commands::id::view(search)?;
                    println!("{}", identity);
                }
                _ => unreachable!("Unknown command")
            }
        }
        Some(("claim", args)) => {
            macro_rules! claim_args {
                ($args:ident) => {{
                    let id = id_val($args)?;
                    let private = $args.get_flag("private");
                    let name = $args.get_one::<String>("claim-name").map(|x| x.as_str());
                    let stage = $args.get_flag("stage");
                    let sign_with = $args.get_one::<String>("admin-key").map(|x| x.as_str());
                    (id, private, name, stage, sign_with)
                }}
            }
            macro_rules! aux_op {
                ($op:expr) => {
                    $op.map_err(|e| format!("Problem adding claim: {}", e))
                }
            }
            macro_rules! save_trans {
                ($transactions:ident, $master_key:ident, $transaction:ident, $stage:ident, $sign_with:ident) => {
                    let identity = util::build_identity(&$transactions)?;
                    let signed = util::sign_helper(&identity, $transaction, &$master_key, $stage, $sign_with)?;
                    commands::dag::save_or_stage($transactions, signed, $stage)?
                }
            }
            macro_rules! easy_claim {
                ($args:ident, $fn:ident, $prompt:expr) => {
                    let (id, private, name, stage, sign_with) = claim_args!($args);
                    let (master_key, transactions, value) = commands::claim::claim_pre(&id, $prompt)?;
                    let trans = aux_op!(stamp_aux::claim::$fn(&master_key, &transactions, value, private, name))?;
                    save_trans!(transactions, master_key, trans, stage, sign_with);
                }
            }
            match args.subcommand() {
                Some(("new", args)) => {
                    match args.subcommand() {
                        Some(("identity", args)) => {
                            easy_claim! { args, new_id, "Enter the ID of your other identity" }
                        }
                        Some(("name", args)) => {
                            easy_claim! { args, new_name, "Enter your name" }
                        }
                        Some(("birthday", args)) => {
                            easy_claim! { args, new_birthday, "Enter your date of birth (eg 1987-11-23)" }
                        }
                        Some(("email", args)) => {
                            easy_claim! { args, new_email, "Enter your email" }
                        }
                        Some(("photo", args)) => {
                            let (id, private, name, stage, sign_with) = claim_args!(args);
                            let photofile = args.get_one::<String>("PHOTO")
                                .map(|x| x.as_str())
                                .ok_or(format!("Must specify a photo"))?;

                            let photo_bytes = util::read_file(photofile)?;
                            if photo_bytes.len() > stamp_aux::claim::MAX_PHOTO_BYTES {
                                Err(format!("Please choose a photo smaller than {} bytes (given photo is {} bytes)", stamp_aux::claim::MAX_PHOTO_BYTES, photo_bytes.len()))?;
                            }
                            let (master_key, transactions) = commands::claim::claim_pre_noval(&id)?;
                            let trans = aux_op!(stamp_aux::claim::new_photo(&master_key, &transactions, photo_bytes, private, name))?;
                            save_trans!(transactions, master_key, trans, stage, sign_with);
                        }
                        Some(("pgp", args)) => {
                            easy_claim! { args, new_pgp, "Enter your PGP ID" }
                        }
                        Some(("domain", args)) => {
                            easy_claim! { args, new_domain, "Enter your domain name" }
                        }
                        Some(("url", args)) => {
                            easy_claim! { args, new_url, "Enter the URL you own" }
                        }
                        Some(("address", args)) => {
                            easy_claim! { args, new_address, "Enter your address" }
                        }
                        Some(("relation", args)) => {
                            let (id, private, name, stage, sign_with) = claim_args!(args);
                            let ty = args.get_one::<String>("TYPE")
                                .map(|x| x.as_str())
                                .ok_or(format!("Must specify a relationship type"))?;
                            let reltype = match ty {
                                "org" => RelationshipType::OrganizationMember,
                                _ => Err(format!("Invalid relationship type: {}", ty))?,
                            };
                            let (master_key, transactions, value) = commands::claim::claim_pre(&id, "Enter the full Stamp identity id for the entity you are related to")?;
                            let trans = aux_op!(stamp_aux::claim::new_relation(&master_key, &transactions, reltype, value, private, name))?;
                            save_trans!(transactions, master_key, trans, stage, sign_with);
                        }
                        _ => unreachable!("Unknown command"),
                    }
                }
                Some(("check", args)) => {
                    let claim_id = args.get_one::<String>("CLAIM")
                        .map(|x| x.as_str())
                        .ok_or(format!("Must specify a claim ID"))?;
                    commands::claim::check(claim_id)?;
                }
                Some(("view", args)) => {
                    let id = id_val(args)?;
                    let output = args.get_one::<String>("output")
                        .map(|x| x.as_str())
                        .unwrap_or("-");
                    let claim_id = args.get_one::<String>("CLAIM")
                        .map(|x| x.as_str())
                        .ok_or(format!("Must specify a claim ID"))?;
                    commands::claim::view(&id, claim_id, output)?;
                }
                Some(("list", args)) => {
                    let id = id_val(args)?;
                    let private = args.get_flag("private");
                    let verbose = args.get_flag("verbose");
                    commands::claim::list(&id, private, verbose)?;
                }
                Some(("delete", args)) => {
                    let id = id_val(args)?;
                    let claim_id = args.get_one::<String>("CLAIM")
                        .map(|x| x.as_str())
                        .ok_or(format!("Must specify a claim ID"))?;
                    let transactions = commands::id::try_load_single_identity(&id)?;
                    let identity = util::build_identity(&transactions)?;
                    if !util::yesno_prompt(&format!("Really delete the claim {} and all of its stamps? [y/N]", claim_id), "n")? {
                        return Ok(());
                    }
                    let master_key = util::passphrase_prompt(&format!("Your master passphrase for identity {}", IdentityID::short(&id)), identity.created())?;
                    let trans = aux_op!(stamp_aux::claim::delete(&transactions, &claim_id))?;
                }
                _ => unreachable!("Unknown command")
            }
        }
        Some(("stamp", args)) => {
            match args.subcommand() {
                Some(("new", args)) => {
                    let our_identity_id = id_val(args)?;
                    let claim_id = args.get_one::<String>("CLAIM")
                        .map(|x| x.as_str())
                        .ok_or(format!("Must specify a claim"))?;
                    let output = args.get_one::<String>("output")
                        .map(|x| x.as_str())
                        .unwrap_or("-");
                    let stage = args.get_flag("stage");
                    let sign_with = args.get_one::<String>("admin-key").map(|x| x.as_str());
                    commands::stamp::new(&our_identity_id, claim_id, stage, sign_with)?;
                }
                /*
                Some(("req", args)) => {
                    drop(args);
                    unimplemented!();
                }
                Some(("list", args)) => {
                    drop(args);
                    unimplemented!();
                }
                Some(("accept", args)) => {
                    let identity_id = id_val(args)?;
                    let location = args.get_one::<String>("LOCATION")
                        .map(|x| x.as_str())
                        .ok_or(format!("Must specify a stamp location"))?;
                    commands::stamp::accept(&identity_id, location)?;
                }
                */
                Some(("revoke", args)) => {
                    drop(args);
                    unimplemented!();
                }
                _ => unreachable!("Unknown command")
            }
        }
        Some(("keychain", args)) => {
            match args.subcommand() {
                Some(("new", args)) => {
                    macro_rules! parse_new_key_args {
                        ($args:ident) => {{
                            let id = id_val($args)?;
                            let name = $args.get_one::<String>("NAME")
                                .map(|x| x.as_str())
                                .ok_or(format!("Must specify a name"))?;
                            let desc = $args.get_one::<String>("description")
                                .map(|x| x.as_str());
                            let stage = $args.get_flag("stage");
                            let sign_with = $args.get_one::<String>("admin-key").map(|x| x.as_str());
                            (id, name, desc, stage, sign_with)
                        }}
                    }
                    match args.subcommand() {
                        Some(("admin", args)) => {
                            let (id, name, desc, stage, sign_with) = parse_new_key_args!(args);
                            commands::keychain::new(&id, "admin", name, desc, stage, sign_with)?;
                        }
                        Some(("sign", args)) => {
                            let (id, name, desc, stage, sign_with) = parse_new_key_args!(args);
                            commands::keychain::new(&id, "sign", name, desc, stage, sign_with)?;
                        }
                        Some(("crypto", args)) => {
                            let (id, name, desc, stage, sign_with) = parse_new_key_args!(args);
                            commands::keychain::new(&id, "crypto", name, desc, stage, sign_with)?;
                        }
                        Some(("secret", args)) => {
                            let (id, name, desc, stage, sign_with) = parse_new_key_args!(args);
                            commands::keychain::new(&id, "secret", name, desc, stage, sign_with)?;
                        }
                        _ => unreachable!("Unknown command")
                    }
                }
                Some(("list", args)) => {
                    let id = id_val(args)?;
                    let ty = args.get_one::<String>("type")
                        .map(|x| x.as_str());
                    let revoked = args.get_flag("revoked");
                    let search = args.get_one::<String>("SEARCH")
                        .map(|x| x.as_str());
                    commands::keychain::list(&id, ty, revoked, search)?;
                }
                Some(("update", args)) => {
                    let id = id_val(args)?;
                    let search = args.get_one::<String>("SEARCH")
                        .map(|x| x.as_str())
                        .ok_or(format!("Must specify a key id or name"))?;
                    let name = args.get_one::<String>("name")
                        .map(|x| x.as_str());
                    let desc = args.get_one::<String>("description")
                        .map(|x| x.as_str())
                        .map(|x| if x == "-" { None } else { Some(x) });
                    let stage = args.get_flag("stage");
                    let sign_with = args.get_one::<String>("admin-key").map(|x| x.as_str());
                    commands::keychain::update(&id, search, name, desc, stage, sign_with)?;
                }
                Some(("revoke", args)) => {
                    let id = id_val(args)?;
                    let stage = args.get_flag("stage");
                    let sign_with = args.get_one::<String>("admin-key").map(|x| x.as_str());
                    let reason = args.get_one::<String>("reason")
                        .map(|x| x.as_str())
                        .unwrap_or("unspecified");
                    let search = args.get_one::<String>("SEARCH")
                        .map(|x| x.as_str())
                        .ok_or(format!("Must specify a key id or name"))?;
                    commands::keychain::revoke(&id, search, reason, stage, sign_with)?;
                }
                Some(("delete-subkey", args)) => {
                    let id = id_val(args)?;
                    let stage = args.get_flag("stage");
                    let sign_with = args.get_one::<String>("admin-key").map(|x| x.as_str());
                    let search = args.get_one::<String>("SEARCH")
                        .map(|x| x.as_str())
                        .ok_or(format!("Must specify a key id or name"))?;
                    commands::keychain::delete_subkey(&id, search, stage, sign_with)?;
                }
                Some(("passwd", args)) => {
                    let id = id_val(args)?;
                    let keyfile = args.get_one::<String>("keyfile")
                        .map(|x| x.as_str());
                    let keyparts: Vec<&str> = args.get_many::<String>("KEYPARTS")
                        .unwrap_or_default()
                        .map(|v| v.as_str())
                        .collect();
                    commands::keychain::passwd(&id, keyfile, keyparts)?;
                }
                Some(("keyfile", args)) => {
                    let id = id_val(args)?;
                    let shamir = args.get_one::<String>("shamir")
                        .map(|x| x.as_str())
                        .unwrap_or("1/1");
                    let output = args.get_one::<String>("output")
                        .map(|x| x.as_str())
                        .unwrap_or("-");
                    commands::keychain::keyfile(&id, shamir, output)?;
                }
                _ => unreachable!("Unknown command")
            }
        }
        Some(("message", args)) => {
            match args.subcommand() {
                Some(("send", args)) => {
                    let from_id = id_val(args)?;
                    let key_from_search = args.get_one::<String>("key-from")
                        .map(|x| x.as_str());
                    let key_to_search = args.get_one::<String>("key-to")
                        .map(|x| x.as_str());
                    let output = args.get_one::<String>("output")
                        .map(|x| x.as_str())
                        .unwrap_or("-");
                    let search = args.get_one::<String>("SEARCH")
                        .map(|x| x.as_str())
                        .ok_or(format!("Must specify a search value"))?;
                    let input = args.get_one::<String>("MESSAGE")
                        .map(|x| x.as_str())
                        .unwrap_or("-");
                    let base64 = args.get_flag("base64");
                    commands::message::send(&from_id, key_from_search, key_to_search, input, output, search, base64)?;
                }
                Some(("send-anonymous", args)) => {
                    let key_to_search = args.get_one::<String>("key-to")
                        .map(|x| x.as_str());
                    let output = args.get_one::<String>("output")
                        .map(|x| x.as_str())
                        .unwrap_or("-");
                    let search = args.get_one::<String>("SEARCH")
                        .map(|x| x.as_str())
                        .ok_or(format!("Must specify a search value"))?;
                    let input = args.get_one::<String>("MESSAGE")
                        .map(|x| x.as_str())
                        .unwrap_or("-");
                    let base64 = args.get_flag("base64");
                    commands::message::send_anonymous(key_to_search, input, output, search, base64)?;
                }
                Some(("open", args)) => {
                    let to_id = id_val(args)?;
                    let key_open = args.get_one::<String>("key-open")
                        .map(|x| x.as_str());
                    let output = args.get_one::<String>("output")
                        .map(|x| x.as_str())
                        .unwrap_or("-");
                    let input = args.get_one::<String>("ENCRYPTED")
                        .map(|x| x.as_str())
                        .unwrap_or("-");
                    commands::message::open(&to_id, key_open, input, output)?;
                }
                _ => unreachable!("Unknown command")
            }
        }
        Some(("signature", args)) => {
            match args.subcommand() {
                Some(("sign", args)) => {
                    let sign_id = id_val(args)?;
                    let key_sign_search = args.get_one::<String>("key-sign")
                        .map(|x| x.as_str());
                    let output = args.get_one::<String>("output")
                        .map(|x| x.as_str())
                        .unwrap_or("-");
                    let input = args.get_one::<String>("MESSAGE")
                        .map(|x| x.as_str())
                        .unwrap_or("-");
                    let attached = args.get_flag("attached");
                    let base64 = args.get_flag("base64");
                    commands::sign::sign(&sign_id, key_sign_search, input, output, attached, base64)?;
                }
                Some(("verify", args)) => {
                    let signature = args.get_one::<String>("SIGNATURE")
                        .map(|x| x.as_str())
                        .unwrap_or("-");
                    let input = args.get_one::<String>("MESSAGE")
                        .map(|x| x.as_str());
                    commands::sign::verify(signature, input)?;
                }
                _ => unreachable!("Unknown command")
            }
        }
        Some(("config", args)) => {
            match args.subcommand() {
                Some(("set-default", args)) => {
                    let search = args.get_one::<String>("SEARCH")
                        .map(|x| x.as_str())
                        .ok_or(format!("Must specify a search value"))?;
                    commands::config::set_default(search)?;
                }
                _ => unreachable!("Unknown command")
            }
        }
        Some(("dag", args)) => {
            match args.subcommand() {
                Some(("list", args)) => {
                    let id = id_val(args)?;
                    commands::dag::list(&id)?;
                }
                Some(("reset", args)) => {
                    let id = id_val(args)?;
                    let txid = args.get_one::<String>("TXID")
                        .map(|x| x.as_str())
                        .ok_or(format!("Must specify a TXID"))?;
                    commands::dag::reset(&id, txid)?;
                }
                _ => unreachable!("Unknown command")
            }
        }
        Some(("debug", args)) => {
            match args.subcommand() {
                Some(("resave", args)) => {
                    // no default here, debug commands should be explicit
                    let id = args.get_one::<String>("identity")
                        .map(|x| x.as_str())
                        .ok_or(format!("Must specify an ID"))?;
                    commands::debug::resave(id)?;
                }
                _ => unreachable!("Unknown command")
            }
        }
        Some(("stage", args)) => {
            match args.subcommand() {
                Some(("list", args)) => {
                    let id = id_val(args)?;
                    commands::stage::list(&id)?;
                }
                Some(("view", args)) => {
                    let txid = args.get_one::<String>("TXID")
                        .map(|x| x.as_str())
                        .ok_or(format!("Must specify a join token"))?;
                    commands::stage::view(txid)?;
                }
                Some(("delete", args)) => {
                    let txid = args.get_one::<String>("TXID")
                        .map(|x| x.as_str())
                        .ok_or(format!("Must specify a join token"))?;
                    commands::stage::delete(txid)?;
                }
                Some(("sign", args)) => {
                    let txid = args.get_one::<String>("TXID")
                        .map(|x| x.as_str())
                        .ok_or(format!("Must specify a join token"))?;
                    let sign_with = args.get_one::<String>("admin-key").map(|x| x.as_str())
                        .ok_or(format!("Must specify an admin key to sign with"))?;
                    commands::stage::sign(txid, sign_with)?;
                }
                Some(("apply", args)) => {
                    let txid = args.get_one::<String>("TXID")
                        .map(|x| x.as_str())
                        .ok_or(format!("Must specify a join token"))?;
                    commands::stage::apply(txid)?;
                }
                _ => unreachable!("Unknown command")
            }
        }
        /*
        Some(("sync", args)) => {
            match args.subcommand() {
                Some(("listen", args)) => {
                    let token = args.get_one::<SyncToken>("TOKEN")
                        .ok_or(format!("Must specify a join token"))?
                        .clone();
                    let bind = args.get_one::<Multiaddr>("bind")
                        .expect("Missing `bind` argument.")
                        .clone();
                    let join = args.get_many::<Multiaddr>("join")
                        .into_iter()
                        .flatten()
                        .map(|x| x.clone())
                        .collect::<Vec<_>>();
                    commands::sync::listen(&token, bind, join)?;
                }
                Some(("run", args)) => {
                    let id = args.get_one::<String>("identity")
                        .map(|x| String::from(x))
                        .or_else(|| {
                            if let Some(id_full) = conf.default_identity.as_ref() {
                                eprintln!("Selecting default identity {} (override with `--id <ID>`)\n", IdentityID::short(&id_full));
                            }
                            conf.default_identity.clone()
                        });
                    let token = args.get_one::<SyncToken>("TOKEN")
                        .map(|x| x.clone());
                    if id.is_none() && token.is_none() {
                        Err(format!("Please specify either --identity or <TOKEN>"))?;
                    }
                    let join = args.get_many::<Multiaddr>("join")
                        .into_iter()
                        .flatten()
                        .map(|x| x.clone())
                        .collect::<Vec<_>>();
                    commands::sync::run(id, token, join)?;
                }
                Some(("token", args)) => {
                    let id = id_val(args)?;
                    let blind = args.get_flag("blind");
                    let regen = args.get_flag("regen");
                    commands::sync::token(&id, blind, regen)?;
                }
                _ => unreachable!("Unknown command")
            }
        }
        */
        _ => unreachable!("Unknown command")
    }
    Ok(())
}

fn main() {
    match run() {
        Ok(_) => {}
        Err(err) => {
            let red = dialoguer::console::Style::new().red();
            eprintln!("{}", red.apply_to(err));
        }
    }
}

