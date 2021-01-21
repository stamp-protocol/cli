use prettytable::Table;
use stamp_core::{
    key::SecretKey,
    identity::VersionedIdentity,
    util::Lockable,
};
use textwrap;

pub(crate) fn term_maxwidth() -> usize { 120 }

pub(crate) fn yesno_prompt(prompt: &str, default: &str) -> Result<bool, String> {
    let yesno: String = dialoguer::Input::new()
        .with_prompt(prompt)
        .default(default.into())
        .show_default(false)
        .interact_text()
        .map_err(|e| format!("Error grabbing retry input: {:?}", e))?;
    if let Some(ynchar) = yesno.chars().next() {
        if ynchar == 'y' || ynchar == 'Y' {
            return Ok(true);
        }
    }
    return Ok(false);
}

/// Grab a password and use it along with a timestamp to generate a master key.
pub(crate) fn passphrase_prompt<T: Into<String>>(prompt: T, now: &stamp_core::util::Timestamp) -> Result<SecretKey, String> {
    let mut passphrase = dialoguer::Password::new().with_prompt(prompt).interact()
        .map_err(|err| format!("There was an error grabbing your passphrase: {:?}", err))?;
    passphrase.mem_lock().map_err(|_| format!("Unable to lock memory for passphrase."))?;
    let salt_bytes = stamp_core::util::hash(format!("{}", now.format("%+")).as_bytes())
        .map_err(|err| format!("Error deriving master key salt: {:?}", err))?;
    let mut master_key = stamp_core::key::derive_master_key(passphrase.as_bytes(), salt_bytes.as_ref(), 2, 67108864)
        .map_err(|err| format!("Problem generating master key: {:?}", err))?;
    master_key.mem_lock()
        .map_err(|_| format!("Unable to lock memory for master key."))?;
    passphrase.mem_unlock().map_err(|_| format!("Unable to unlock passphrase memory."))?;
    Ok(master_key)
}

pub(crate) fn with_new_passphrase<F, T>(prompt: &str, gen_fn: F, now: Option<stamp_core::util::Timestamp>) -> Result<(T, SecretKey), String>
    where F: FnOnce(&stamp_core::key::SecretKey, stamp_core::util::Timestamp) -> Result<T, String>,
{
    let mut passphrase = dialoguer::Password::new().with_prompt(prompt).interact()
        .map_err(|err| format!("There was an error grabbing your passphrase: {:?}", err))?;
    let mut confirm = dialoguer::Password::new().with_prompt("Confirm passphrase").interact()
        .map_err(|err| format!("There was an error grabbing your confirmation: {:?}", err))?;
    passphrase.mem_lock().map_err(|_| format!("Unable to lock memory for passphrase."))?;
    confirm.mem_lock().map_err(|_| format!("Unable to lock memory for confirmation."))?;
    if passphrase != confirm {
        if yesno_prompt("Passphrase and confirmation do not match. Try again? [Y/n]", "y")? {
            return with_new_passphrase(prompt, gen_fn, now);
        }
        return Err(String::from("Passphrase mismatch"));
    }
    confirm.mem_unlock().map_err(|_| format!("Unable to unlock confirmation memory."))?;
    let now = now.unwrap_or_else(|| stamp_core::util::Timestamp::now());
    let salt_bytes = stamp_core::util::hash(format!("{}", now.format("%+")).as_bytes())
        .map_err(|err| format!("Error deriving master key salt: {:?}", err))?;
    let mut master_key = stamp_core::key::derive_master_key(passphrase.as_bytes(), salt_bytes.as_ref(), 2, 67108864)
        .map_err(|err| format!("Problem generating master key: {:?}", err))?;
    master_key.mem_lock()
        .map_err(|_| format!("Unable to lock memory for master key."))?;
    passphrase.mem_unlock().map_err(|_| format!("Unable to unlock passphrase memory."))?;

    let res = gen_fn(&master_key, now);
    Ok((res?, master_key))
}

/// Output a table of identities.
pub fn print_identities_table(identities: &Vec<VersionedIdentity>, verbose: bool) {
    let mut table = Table::new();
    table.set_format(*prettytable::format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
    table.set_titles(row!["Mine", "ID", "Nickname", "Name", "Email", "Created"]);
    for identity in identities {
        let id_full = identity.id_string();
        let id_short = &id_full[0..16];
        let nickname = identity.nickname_maybe().unwrap_or(String::from(""));
        let name = identity.name_maybe().unwrap_or(String::from(""));
        let email = identity.email_maybe().unwrap_or(String::from(""));
        let created = identity.created().local().format("%b %d, %Y").to_string();
        let owned = if identity.is_owned() { "x" } else { "" };
        table.add_row(row![
            owned,
            if verbose { &id_full } else { id_short },
            nickname,
            name,
            email,
            created,
        ]);
    }
    table.printstd();
}

pub fn print_wrapped(text: &str) {
    let lines = textwrap::wrap(text, std::cmp::min(textwrap::termwidth(), term_maxwidth()));
    for line in lines {
        println!("{}", line);
    }
}

