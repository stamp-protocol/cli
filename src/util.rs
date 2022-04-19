use stamp_core::{
    crypto::key::{KDF_OPS_MODERATE, KDF_MEM_MODERATE, SecretKey},
    dag::Transactions,
    identity::Identity,
};
use std::fs::File;
use std::io::{BufReader, Read, Write};
use textwrap;

pub(crate) fn term_maxwidth() -> usize { 120 }

pub(crate) fn yesno_prompt(prompt: &str, default: &str) -> Result<bool, String> {
    let yesno: String = dialoguer::Input::new()
        .with_prompt(&text_wrap(prompt))
        .default(default.into())
        .show_default(false)
        .interact_text()
        .map_err(|e| format!("Error grabbing input: {:?}", e))?;
    if let Some(ynchar) = yesno.chars().next() {
        if ynchar == 'y' || ynchar == 'Y' {
            return Ok(true);
        }
    }
    return Ok(false);
}

pub(crate) fn value_prompt(prompt: &str) -> Result<String, String> {
    let val: String = dialoguer::Input::new()
        .with_prompt(prompt)
        .interact_text()
        .map_err(|e| format!("Error grabbing input: {:?}", e))?;
    return Ok(val);
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
                let id_short = stamp_core::identity::IdentityID::short(&id_full);
                (id_full, id_short)
             }
            Err(..) => (String::from("<error serializing ID>"), String::from("<error serializing ID>")),
        }
    }
}

pub(crate) fn build_identity(transactions: &Transactions) -> Result<Identity, String> {
    transactions.build_identity()
        .map_err(|e| format!("Problem building identity: {:?}", e))
}

fn derive_master(passphrase: &str, now: &stamp_core::util::Timestamp) -> Result<SecretKey, String> {
    let salt_bytes = stamp_core::util::hash(format!("{}", now.format("%+")).as_bytes())
        .map_err(|err| format!("Error deriving master key salt: {:?}", err))?;
    let master_key = stamp_core::crypto::key::derive_master_key(passphrase.as_bytes(), salt_bytes.as_ref(), KDF_OPS_MODERATE, KDF_MEM_MODERATE)
        .map_err(|err| format!("Problem generating master key: {:?}", err))?;
    Ok(master_key)
}

/// Grab a password and use it along with a timestamp to generate a master key.
pub(crate) fn passphrase_prompt<T: Into<String>>(prompt: T, now: &stamp_core::util::Timestamp) -> Result<SecretKey, String> {
    let passphrase = dialoguer::Password::new().with_prompt(prompt).interact()
        .map_err(|err| format!("There was an error grabbing your passphrase: {:?}", err))?;
    derive_master(&passphrase, now)
}

pub(crate) fn with_new_passphrase<F, T>(prompt: &str, gen_fn: F, now: Option<stamp_core::util::Timestamp>) -> Result<(T, SecretKey), String>
    where F: FnOnce(&stamp_core::crypto::key::SecretKey, stamp_core::util::Timestamp) -> Result<T, String>,
{
    let passphrase = dialoguer::Password::new().with_prompt(prompt).interact()
        .map_err(|err| format!("There was an error grabbing your passphrase: {:?}", err))?;
    let confirm = dialoguer::Password::new().with_prompt("Confirm passphrase").interact()
        .map_err(|err| format!("There was an error grabbing your confirmation: {:?}", err))?;
    if passphrase != confirm {
        if yesno_prompt("Passphrase and confirmation do not match. Try again? [Y/n]", "y")? {
            return with_new_passphrase(prompt, gen_fn, now);
        }
        return Err(String::from("Passphrase mismatch"));
    }
    let now = now.unwrap_or_else(|| stamp_core::util::Timestamp::now());
    let master_key = derive_master(&passphrase, &now)?;
    let res = gen_fn(&master_key, now);
    Ok((res?, master_key))
}

pub fn read_file(filename: &str) -> Result<Vec<u8>, String> {
    if filename == "-" {
        if atty::is(atty::Stream::Stdin) {
            let mut contents = String::new();
            let stdin = std::io::stdin();
            eprintln!("{}", text_wrap("Enter your message and hit enter/return:"));
            stdin.read_line(&mut contents)
                .map_err(|e| format!("Problem reading file: {}: {:?}", filename, e))?;
            Ok(Vec::from(contents.trim_end_matches('\n').trim_end_matches('\r').as_bytes()))
        } else {
            let mut contents = Vec::new();
            let mut stdin = std::io::stdin();
            stdin.read_to_end(&mut contents)
                .map_err(|e| format!("Problem reading file: {}: {:?}", filename, e))?;
            Ok(contents)
        }
    } else {
        load_file(filename)
    }
}

pub fn write_file(filename: &str, bytes: &[u8]) -> Result<(), String> {
    if filename == "-" {
        let mut out = std::io::stdout();
        out.write_all(bytes)
            .map_err(|e| format!("There was a problem outputting the identity: {:?}", e))?;
        out.flush()
            .map_err(|e| format!("There was a problem outputting the identity: {:?}", e))?;
        println!("");
    } else {
        let mut handle = File::create(&filename)
            .map_err(|e| format!("Error opening file: {}: {:?}", filename, e))?;
        handle.write_all(bytes)
            .map_err(|e| format!("Error writing to identity file: {}: {:?}", filename, e))?;
    }
    Ok(())
}

pub fn load_file(filename: &str) -> Result<Vec<u8>, String> {
    let file = File::open(filename)
        .map_err(|e| format!("Unable to open file: {}: {:?}", filename, e))?;
    let mut reader = BufReader::new(file);
    let mut contents = Vec::new();
    reader.read_to_end(&mut contents)
        .map_err(|e| format!("Problem reading file: {}: {:?}", filename, e))?;
    Ok(contents)
}

pub fn text_wrap(text: &str) -> String {
    textwrap::fill(text, std::cmp::min(textwrap::termwidth(), term_maxwidth()))
}

pub fn print_wrapped(text: &str) {
    let lines = text_wrap(text);
    print!("{}", lines);
}

pub fn print_wrapped_indent(text: &str, indent: &str) {
    let lines = text_wrap(text);
    let indented = textwrap::indent(lines.as_str(), indent);
    print!("{}", indented);
}

