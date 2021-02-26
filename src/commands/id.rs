use crate::{
    config,
    db,
    util
};
use indicatif::{ProgressBar, ProgressStyle};
use prettytable::Table;
use stamp_core::{
    crypto::key::{SecretKey, SignKeypair, CryptoKeypair},
    dag::Transactions,
    identity::{ExtendKeypair, AlphaKeypair, PolicyKeypair, PublishKeypair, RootKeypair, Key, IdentityID, Identity, ClaimSpec, PublishedIdentity},
    private::{Private, MaybePrivate},
    util::{Timestamp, SerdeBinary},
};
use std::convert::TryFrom;
use std::ops::Deref;

fn passphrase_note() {
    util::print_wrapped("To protect your identity from unauthorized access, enter a long but memorable master passphrase. Choose something personal that is easy for you to remember but hard for someone else to guess.\n\n  Example: my dog butch has a friend named snow\n\nYou can change this later using the `stamp keychain passwd` command.\n\n");
}

fn prompt_claim_name_email(master_key: &SecretKey, transactions: Transactions) -> Result<Transactions, String> {
    println!("It's a good idea to associate your name and email with your identity.");
    if !util::yesno_prompt("Would you like to do this? [Y/n]", "y")? {
        return Ok(transactions);
    }
    let name: String = dialoguer::Input::new()
        .with_prompt("Your full name")
        .interact_text()
        .map_err(|e| format!("Error grabbing name input: {:?}", e))?;
    let email: String = dialoguer::Input::new()
        .with_prompt("Your primary email")
        .interact_text()
        .map_err(|e| format!("Error grabbing email input: {:?}", e))?;
    let transactions = transactions
        .make_claim(master_key, Timestamp::now(), ClaimSpec::Name(MaybePrivate::new_public(name)))
        .map_err(|e| format!("Error generating name claim: {}", e))?
        .make_claim(master_key, Timestamp::now(), ClaimSpec::Email(MaybePrivate::new_public(email)))
        .map_err(|e| format!("Error generating email claim: {}", e))?;
    Ok(transactions)
}

pub fn try_load_single_identity(id: &str) -> Result<Transactions, String> {
    let identities = db::load_identities_by_prefix(id)?;
    if identities.len() > 1 {
        let identities = identities.iter()
            .map(|x| util::build_identity(&x))
            .collect::<Result<Vec<_>, String>>()?;
        print_identities_table(&identities, false);
        Err(format!("Multiple identities matched that ID"))?;
    } else if identities.len() == 0 {
        Err(format!("No identities matches that ID"))?;
    }
    Ok(identities[0].clone())
}

fn post_create(master_key: &SecretKey, transactions: Transactions) -> Result<(), String> {
    // ask if they want name/email claims, then add three default subkeys (sign,
    // crypto, secret) to their keychain.
    let subkey_sign = SignKeypair::new_ed25519(&master_key)
        .map_err(|e| format!("Error generating subkey: {}", e))?;
    let subkey_crypto = CryptoKeypair::new_curve25519xsalsa20poly1305(&master_key)
        .map_err(|e| format!("Error generating subkey: {}", e))?;
    let subkey_secret = Private::seal(&master_key, &SecretKey::new_xsalsa20poly1305())
        .map_err(|e| format!("Error generating subkey: {}", e))?;
    let identity = util::build_identity(&transactions)?;
    let transactions = transactions
        .make_claim(&master_key, Timestamp::now(), ClaimSpec::Identity(identity.id().clone()))
        .map_err(|e| format!("Problem making identity claim: {}", e))?;
    let transactions = prompt_claim_name_email(&master_key, transactions)?
        .add_subkey(master_key, Timestamp::now(), Key::new_sign(subkey_sign), "default:sign", Some("A default key for signing documents or messages."))
        .map_err(|e| format!("Problem adding key to identity: {}", e))?
        .add_subkey(master_key, Timestamp::now(), Key::new_crypto(subkey_crypto), "default:crypto", Some("A default key for receiving private messages."))
        .map_err(|e| format!("Problem adding key to identity: {}", e))?
        .add_subkey(master_key, Timestamp::now(), Key::new_secret(subkey_secret), "default:secret", Some("A default key allowing encryption/decryption of personal data."))
        .map_err(|e| format!("Problem adding key to identity: {}", e))?;
    let id_str = id_str!(identity.id())?;
    db::save_identity(transactions)?;
    let green = dialoguer::console::Style::new().green();
    let bold = dialoguer::console::Style::new().bold();
    println!("---\n{} The identity {} has been saved.", green.apply_to("Success!"), IdentityID::short(&id_str));
    let mut conf = config::load()?;
    if conf.default_identity.is_none() {
        println!("Marking identity as default.");
        conf.default_identity = Some(id_str);
        config::save(&conf)?;
    }
    let msg = format!("\n{} It's a good idea to either store your master passphrase in a password manager or use the `{}` command to create a backup file that will let you access your identity in the event you lose your master passphrase.\n", bold.apply_to("If you lose your master passphrase, you will be locked out of your identity."), green.apply_to("stamp keychain keyfile"));
    util::print_wrapped(&msg);
    Ok(())
}

pub(crate) fn create_new() -> Result<(), String> {
    passphrase_note();
    let (transactions, master_key) = util::with_new_passphrase("Your master passphrase", |master_key, now| {
        let mapper = |err| format!("Failed to create identity: {:?}", err);
        let alpha = AlphaKeypair::new_ed25519(&master_key).map_err(mapper)?;
        let policy = PolicyKeypair::new_ed25519(&master_key).map_err(mapper)?;
        let publish = PublishKeypair::new_ed25519(&master_key).map_err(mapper)?;
        let root = RootKeypair::new_ed25519(&master_key).map_err(mapper)?;
        let transactions = Transactions::new()
            .create_identity(&master_key, now.clone(), alpha, policy, publish, root).map_err(mapper)?;
        Ok(transactions)
    }, None)?;
    println!("");
    let identity = transactions.build_identity()
        .map_err(|err| format!("Failed to build identity: {:?}", err))?;
    let id_str = id_str!(identity.id())?;
    println!("Generated a new identity with the ID {}", id_str);
    println!("");
    post_create(&master_key, transactions)?;
    Ok(())
}

pub(crate) fn create_vanity(regex: Option<&str>, contains: Vec<&str>, prefix: Option<&str>) -> Result<(), String> {
    let spinner = ProgressBar::new_spinner();
    spinner.enable_steady_tick(250);
    spinner.set_style(
        ProgressStyle::default_spinner()
            .tick_strings(&[
                "      ",
                "*     ",
                " *    ",
                "  *   ",
                "   *  ",
                "    * ",
                "     *",
                "     *",
            ])
            .template("[{spinner:.green}] {msg}")
    );
    spinner.set_message("Starting vanity ID search, this might take a while.");
    let mut counter = 0;
    let regex = if let Some(re) = regex {
        Some(regex::Regex::new(re).map_err(|e| format!("Problem compiling regex: {:?}", e))?)
    } else {
        None
    };
    let mut filter = |id_str: &str| -> bool {
        counter += 1;
        if counter % 1000 == 0 {
            spinner.set_message(&format!("Searched {} IDs", counter));
        }
        if let Some(regex) = regex.as_ref() {
            if !regex.is_match(id_str) {
                return false;
            }
        }
        if let Some(prefix) = prefix {
            if !id_str.starts_with(prefix) {
                return false;
            }
        }
        for needle in &contains {
            if !id_str.contains(needle) {
                return false;
            }
        }
        spinner.finish();
        eprintln!("Found it! {}", id_str);
        return true;
    };

    let mut now;
    let mut transactions;
    let tmp_master_key = SecretKey::new_xsalsa20poly1305();
    let policy_keypair = PolicyKeypair::new_ed25519(&tmp_master_key)
        .map_err(|e| format!("Error generating policy keypair: {:?}", e))?;
    let publish_keypair = PublishKeypair::new_ed25519(&tmp_master_key)
        .map_err(|e| format!("Error generating publish keypair: {:?}", e))?;
    let root_keypair = RootKeypair::new_ed25519(&tmp_master_key)
        .map_err(|e| format!("Error generating root keypair: {:?}", e))?;
    loop {
        now = Timestamp::now();
        let alpha_keypair = AlphaKeypair::new_ed25519(&tmp_master_key)
            .map_err(|e| format!("Error generating alpha keypair: {:?}", e))?;
        transactions = Transactions::new()
            .create_identity(&tmp_master_key, now.clone(), alpha_keypair, policy_keypair.clone(), publish_keypair.clone(), root_keypair.clone())
            .map_err(|e| format!("problem creating identity: {}", e))?;
        let id = IdentityID::from(transactions.transactions()[0].id().deref().clone());
        let based = id_str!(&id)?;
        if filter(&based) {
            break;
        }
    }

    passphrase_note();
    let (_, master_key) = util::with_new_passphrase("Your master passphrase", |_master_key, _now| { Ok(()) }, Some(now.clone()))?;
    let transactions = transactions.reencrypt(&tmp_master_key, &master_key)
        .map_err(|err| format!("Failed to create identity: {}", err))?;
    post_create(&master_key, transactions)?;
    Ok(())
}

pub fn list(search: Option<&str>, verbose: bool) -> Result<(), String> {
    let identities = db::list_local_identities(search)?
        .iter()
        .map(|x| util::build_identity(&x))
        .collect::<Result<Vec<_>, String>>()?;
    print_identities_table(&identities, verbose);
    Ok(())
}

pub fn import(location: &str) -> Result<(), String> {
    let contents = util::load_file(location)?;
    // first try importing an owned identity
    let imported = Transactions::deserialize_binary(contents.as_slice())
        .or_else(|_| {
            PublishedIdentity::deserialize(contents.as_slice())
                .map(|x| x.identity().clone())
        })
        .map_err(|e| format!("Problem loading identity: {:?}", e))?;
    let identity = util::build_identity(&imported)?;
    let exists = db::load_identity(identity.id())?;
    if let Some(existing) = exists {
        if existing.is_owned() && !identity.is_owned() {
            Err(format!("You are attempting to overwrite an existing owned identity with a public identity, which will erase all of your private data."))?;
        }
        if !util::yesno_prompt("The identity you're importing already exists locally. Overwrite? [y/N]", "n")? {
            return Ok(());
        }
    }
    let id_str = id_str!(identity.id())?;
    db::save_identity(imported)?;
    println!("Imported identity {}", id_str);
    Ok(())
}

pub fn publish(id: &str) -> Result<String, String> {
    let transactions = try_load_single_identity(id)?;
    let identity = util::build_identity(&transactions)?;
    let id_str = id_str!(identity.id())?;
    let master_key = util::passphrase_prompt(&format!("Your master passphrase for identity {}", IdentityID::short(&id_str)), identity.created())?;
    let now = Timestamp::now();
    let published = PublishedIdentity::publish(&master_key, now, transactions)
        .map_err(|e| format!("Error creating published identity: {:?}", e))?;
    let serialized = published.serialize()
        .map_err(|e| format!("Error serializing identity: {:?}", e))?;
    Ok(serialized)
}

pub fn export_private(id: &str) -> Result<Vec<u8>, String> {
    let identity = try_load_single_identity(id)?;
    let serialized = identity.serialize_binary()
        .map_err(|e| format!("There was a problem serializing the identity: {:?}", e))?;
    Ok(serialized)
}

pub fn delete(search: &str, skip_confirm: bool, verbose: bool) -> Result<(), String> {
    let identities = db::list_local_identities(Some(search))?;
    if identities.len() == 0 {
        Err(format!("No identities match that search"))?;
    }
    let identities = identities.into_iter()
        .map(|x| util::build_identity(&x))
        .collect::<Result<Vec<_>, String>>()?;
    print_identities_table(&identities, verbose);
    if !skip_confirm {
        let msg = format!("Permanently delete these {} identities? [y/N]", identities.len());
        if !util::yesno_prompt(&msg, "n")? {
            return Ok(());
        }
    }
    let id_len = identities.len();
    for identity in identities {
        let id = id_str!(identity.id())?;
        db::delete_identity(&id)?;
    }
    println!("Deleted {} identities", id_len);
    Ok(())
}

pub fn view(search: &str) -> Result<String, String> {
    let identities = db::list_local_identities(Some(search))?;
    if identities.len() > 1 {
        let identities = identities.iter()
            .map(|x| util::build_identity(&x))
            .collect::<Result<Vec<_>, String>>()?;
        print_identities_table(&identities, false);
        Err(format!("Multiple identities matched that search"))?;
    } else if identities.len() == 0 {
        Err(format!("No identities match that search"))?;
    }
    let transactions = identities[0].clone();
    let identity = util::build_identity(&transactions)?;
    let serialized = identity.serialize()
        .map_err(|e| format!("Problem serializing identity: {:?}", e))?;
    Ok(serialized)
}

/// Output a table of identities.
pub fn print_identities_table(identities: &Vec<Identity>, verbose: bool) {
    let mut table = Table::new();
    table.set_format(*prettytable::format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
    let id_field = if verbose { "ID" } else { "ID (short)" };
    table.set_titles(row!["Mine", id_field, "Nickname", "Name", "Email", "Created"]);
    for identity in identities {
        let (id_full, id_short) = id_str_split!(identity.id());
        let nickname = identity.nickname_maybe().unwrap_or(String::from(""));
        let name = identity.name_maybe().unwrap_or(String::from(""));
        let email = identity.email_maybe().unwrap_or(String::from(""));
        let created = identity.created().local().format("%b %d, %Y").to_string();
        let owned = if identity.is_owned() { "x" } else { "" };
        table.add_row(row![
            owned,
            if verbose { &id_full } else { &id_short },
            nickname,
            name,
            email,
            created,
        ]);
    }
    table.printstd();
}

