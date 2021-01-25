use dirs;
use prettytable::Table;
use stamp_core::{
    key::SecretKey,
    identity::{
        IdentityID,
        ClaimSpec,
        ClaimContainer,
        RelationshipType,
        VersionedIdentity,
    },
    private::MaybePrivate,
    util::Lockable,
};
use std::convert::TryFrom;
use std::path::PathBuf;
use textwrap;

pub fn data_dir() -> Result<PathBuf, String> {
    let mut dir = dirs::data_dir()
        .or_else(|| dirs::home_dir().map(|mut x| { x.push(".stamp"); x }))
        .ok_or(String::from("Cannot find user's home or data directory."))?;
    dir.push("stamp");
    Ok(dir)
}

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

pub fn id_short(id: &str) -> String {
    String::from(&id[0..16])
}

macro_rules! id_str {
    ($id:expr) => {
        String::try_from($id)
            .map_err(|e| format!("There was a problem converting the id {:?} to a string: {:?}", $id, e))
    }
}

macro_rules! id_str_split {
    ($id:expr) => {
        match String::try_from($id) {
            Ok(id_full) => {
                let id_short = id_short(&id_full);
                (id_full, id_short)
             }
            Err(..) => (String::from("<error serializing ID>"), String::from("<error serializing ID>")),
        }
    }
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

pub fn print_claims_table(claims: &Vec<ClaimContainer>, master_key_maybe: Option<SecretKey>, verbose: bool) {
    let mut table = Table::new();
    table.set_format(*prettytable::format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
    table.set_titles(row!["ID", "Type", "Value", "Created", "# stamps"]);
    for claim in claims {
        let (id_full, id_short) = id_str_split!(claim.claim().id());
        let string_from_private = |private: &MaybePrivate<String>| -> String {
            if let Some(master_key) = master_key_maybe.as_ref() {
                private.open(master_key).unwrap_or_else(|e| format!("Decryption error: {:?}", e))
            } else {
                match private {
                    MaybePrivate::Public(val) => val.clone(),
                    MaybePrivate::Private(..) => {
                        String::from("<private>")
                    }
                }
            }
        };
        let (ty, val) = match claim.claim().spec() {
            ClaimSpec::Identity(id) => {
                let (id_full, id_short) = id_str_split!(id);
                ("identity", if verbose { id_full } else { id_short })
            }
            ClaimSpec::Name(name) => ("name", string_from_private(name)),
            ClaimSpec::Email(email) => ("email", string_from_private(email)),
            ClaimSpec::PGP(pgp) => ("pgp", string_from_private(pgp)),
            ClaimSpec::HomeAddress(address) => ("address", string_from_private(address)),
            ClaimSpec::Relation(relation) => {
                let rel_str = match relation {
                    MaybePrivate::Public(relationship) => {
                        let ty_str = match relationship.ty() {
                            RelationshipType::Family => String::from("family"),
                            RelationshipType::Friend => String::from("friend"),
                            RelationshipType::OrganizationMember => String::from("org"),
                            _ => String::from("<unknown>"),
                        };
                        let id: &IdentityID = relationship.who();
                        let (id_full, id_short) = id_str_split!(id);
                        format!("{} ({})", if verbose { id_full } else { id_short }, ty_str)
                    }
                    MaybePrivate::Private(..) => String::from("******"),
                };
                ("relation", rel_str)
            }
            _ => ("<unknown>", String::from("<unknown>")),
        };
        let created = claim.claim().created().local().format("%b %d, %Y").to_string();
        table.add_row(row![
            if verbose { &id_full } else { &id_short },
            ty,
            val,
            created,
            format!("{}", claim.stamps().len()),
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

