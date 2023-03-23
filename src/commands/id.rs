use crate::{
    db,
    util,
};
use indicatif::{ProgressBar, ProgressStyle};
use prettytable::Table;
use stamp_aux::{
    db::stage_transaction,
};
use stamp_core::{
    crypto::base::{SecretKey},
    dag::Transactions,
    identity::{IdentityID, Identity},
    util::{Timestamp, SerdeBinary, SerText},
};
use std::convert::TryFrom;

pub(crate) fn passphrase_note() {
    util::print_wrapped("To protect your identity from unauthorized access, enter a long but memorable master passphrase. Choose something personal that is easy for you to remember but hard for someone else to guess.\n\n  Example: my dog butch has a friend named snow\n\nYou can change this later using the `stamp keychain passwd` command.\n\n");
}

pub(crate) fn prompt_name_email() -> Result<(Option<String>, Option<String>), String> {
    println!("It's a good idea to associate your name and email with your identity.");
    if !util::yesno_prompt("Would you like to do this? [Y/n]", "y")? {
        return Ok((None, None));
    }
    let name: String = dialoguer::Input::new()
        .with_prompt("Your full name")
        .interact_text()
        .map_err(|e| format!("Error grabbing name input: {:?}", e))?;
    let email: String = dialoguer::Input::new()
        .with_prompt("Your primary email")
        .interact_text()
        .map_err(|e| format!("Error grabbing email input: {:?}", e))?;
    Ok((Some(name), Some(email)))
}

pub(crate) fn post_create(transactions: &Transactions) -> Result<(), String> {
    let green = dialoguer::console::Style::new().green();
    let bold = dialoguer::console::Style::new().bold();
    let identity = util::build_identity(transactions)?;
    let id_str = id_str!(identity.id())?;
    println!("---\n{} The identity {} has been saved.", green.apply_to("Success!"), IdentityID::short(&id_str));
    let msg = format!("\n{} It's a good idea to either store your master passphrase in a password manager or use the `{}` command to create a backup file that will let you access your identity in the event you lose your master passphrase.\n", bold.apply_to("If you lose your master passphrase, you will be locked out of your identity."), green.apply_to("stamp keychain keyfile"));
    util::print_wrapped(&msg);
    Ok(())
}

pub(crate) fn try_load_single_identity(id: &str) -> Result<Transactions, String> {
    let identities = db::load_identities_by_prefix(id)?;
    if identities.len() > 1 {
        let identities = identities.iter()
            .map(|x| util::build_identity(&x))
            .collect::<Result<Vec<_>, String>>()?;
        print_identities_table(&identities, false);
        Err(format!("Multiple identities matched ID {}", id))?;
    } else if identities.len() == 0 {
        Err(format!("No identities match the ID {}", id))?;
    }
    Ok(identities[0].clone())
}

pub(crate) fn create_vanity(regex: Option<&str>, contains: Vec<&str>, prefix: Option<&str>) -> Result<(SecretKey, Transactions, Timestamp), String> {
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
    let (tmp_master_key, transactions, now) = stamp_aux::id::create_personal_vanity(regex, contains, prefix, |counter| {
        spinner.set_message(&format!("Searched {} IDs", counter));
    }).map_err(|e| format!("Error generating vanity id: {}", e))?;
    spinner.finish();
    let identity = util::build_identity(&transactions)?;
    let id_str = id_str!(identity.id())?;
    let green = dialoguer::console::Style::new().green();
    eprintln!("\n{} {}\n", green.apply_to("Found it!"), id_str);
    Ok((tmp_master_key, transactions, now))
}

pub fn publish(id: &str, stage: bool, sign_with: Option<&str>) -> Result<String, String> {
    let transactions = try_load_single_identity(id)?;
    let identity = util::build_identity(&transactions)?;
    let id_str = id_str!(identity.id())?;
    let master_key = util::passphrase_prompt(&format!("Your master passphrase for identity {}", IdentityID::short(&id_str)), identity.created())?;
    let now = Timestamp::now();
    let transaction = transactions.publish(now)
        .map_err(|e| format!("Error creating publish transaction: {:?}", e))?;

    let signed = util::sign_helper(&identity, transaction, &master_key, stage, sign_with)?;
    if stage {
        let transaction = stage_transaction(identity.id(), signed)
            .map_err(|e| format!("Error staging transaction: {:?}", e))?;
        id_str!(transaction.id())
    } else {
        signed.serialize_text()
            .map_err(|e| format!("Error serializing transaction: {:?}", e))
    }
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
    let serialized = identity.serialize_text()
        .map_err(|e| format!("Problem serializing identity: {:?}", e))?;
    Ok(serialized)
}

/// Output a table of identities.
pub(crate) fn print_identities_table(identities: &Vec<Identity>, verbose: bool) {
    let mut table = Table::new();
    table.set_format(*prettytable::format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
    let id_field = if verbose { "ID" } else { "ID (short)" };
    table.set_titles(row!["Mine", id_field, "Name", "Email", "Created"]);
    for identity in identities {
        let (id_full, id_short) = id_str_split!(identity.id());
        let name = identity.names().get(0).map(|x| x.clone()).unwrap_or_else(|| String::from(""));
        let email = identity.emails().get(0).map(|x| x.clone()).unwrap_or_else(|| String::from(""));
        let created = identity.created().local().format("%b %d, %Y").to_string();
        let owned = if identity.is_owned() { "x" } else { "" };
        table.add_row(row![
            owned,
            if verbose { &id_full } else { &id_short },
            name,
            email,
            created,
        ]);
    }
    table.printstd();
}

