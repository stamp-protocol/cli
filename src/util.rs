use stamp_core::{
    key::SecretKey,
    util::Lockable,
};

pub(crate) fn passphrase_note() {
    println!("");
    println!("To protect your identity, enter a long but memorable passphrase.");
    println!("Choose something personal that is easy for you to remember but hard for someone else to guess.");
    println!("Example: my dog butch has a friend named snow");
    println!("");
}

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

