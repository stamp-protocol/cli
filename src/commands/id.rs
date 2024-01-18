use anyhow::{anyhow, Result};
use crate::{
    config,
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

pub(crate) enum FingerprintFormat {
    Svg,
    Term,
}

pub(crate) fn passphrase_note() {
    util::print_wrapped("To protect your identity from unauthorized access, enter a long but memorable master passphrase. Choose something personal that is easy for you to remember but hard for someone else to guess.\n\n  Example: my dog butch has a friend named snow\n\nYou can change this later using the `stamp keychain passwd` command.\n\n");
}

pub(crate) fn prompt_name_email() -> Result<(Option<String>, Option<String>)> {
    println!("It's a good idea to associate your name and email with your identity.");
    if !util::yesno_prompt("Would you like to do this? [Y/n]", "y")? {
        return Ok((None, None));
    }
    let name: String = dialoguer::Input::new()
        .with_prompt("Your full name")
        .interact_text()
        .map_err(|e| anyhow!("Error grabbing name input: {:?}", e))?;
    let email: String = dialoguer::Input::new()
        .with_prompt("Your primary email")
        .interact_text()
        .map_err(|e| anyhow!("Error grabbing email input: {:?}", e))?;
    Ok((Some(name), Some(email)))
}

pub(crate) fn post_create(transactions: &Transactions) -> Result<()> {
    let green = dialoguer::console::Style::new().green();
    let bold = dialoguer::console::Style::new().bold();
    let identity = util::build_identity(transactions)?;
    let id_str = id_str!(identity.id())?;
    println!("---\n{} The identity {} has been saved.", green.apply_to("Success!"), IdentityID::short(&id_str));
    let msg = format!("\n{} It's a good idea to either store your master passphrase in a password manager or use the `{}` command to create a backup file that will let you access your identity in the event you lose your master passphrase.\n", bold.apply_to("If you lose your master passphrase, you will be locked out of your identity."), green.apply_to("stamp keychain keyfile"));
    util::print_wrapped(&msg);
    Ok(())
}

pub(crate) fn try_load_single_identity(id: &str) -> Result<Transactions> {
    let identities = db::load_identities_by_prefix(id)?;
    if identities.len() > 1 {
        let identities = identities.iter()
            .map(|x| util::build_identity(x))
            .collect::<Result<Vec<_>>>()?;
        print_identities_table(&identities, false);
        Err(anyhow!("Multiple identities matched ID {}", id))?;
    } else if identities.len() == 0 {
        Err(anyhow!("No identities match the ID {}", id))?;
    }
    Ok(identities[0].clone())
}

pub(crate) fn create_vanity(regex: Option<&str>, contains: Vec<&str>, prefix: Option<&str>) -> Result<(SecretKey, Transactions, Timestamp)> {
    let hash_with = config::hash_algo(None);
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
    let (tmp_master_key, transactions, now) = stamp_aux::id::create_personal_vanity(&hash_with, regex, contains, prefix, |counter| {
        spinner.set_message(&format!("Searched {} IDs", counter));
    }).map_err(|e| anyhow!("Error generating vanity id: {}", e))?;
    spinner.finish();
    let identity = util::build_identity(&transactions)?;
    let id_str = id_str!(identity.id())?;
    let green = dialoguer::console::Style::new().green();
    eprintln!("\n{} {}\n", green.apply_to("Found it!"), id_str);
    Ok((tmp_master_key, transactions, now))
}

pub fn publish(id: &str, stage: bool, sign_with: Option<&str>) -> Result<String> {
    let hash_with = config::hash_algo(Some(&id));
    let transactions = try_load_single_identity(id)?;
    let identity = util::build_identity(&transactions)?;
    let id_str = id_str!(identity.id())?;
    let master_key = util::passphrase_prompt(&format!("Your master passphrase for identity {}", IdentityID::short(&id_str)), identity.created())?;
    let now = Timestamp::now();
    let transaction = transactions.publish(&hash_with, now)
        .map_err(|e| anyhow!("Error creating publish transaction: {:?}", e))?;

    let signed = util::sign_helper(&identity, transaction, &master_key, stage, sign_with)?;
    if stage {
        let transaction = stage_transaction(identity.id(), signed)
            .map_err(|e| anyhow!("Error staging transaction: {:?}", e))?;
        id_str!(transaction.id())
    } else {
        signed.serialize_text()
            .map_err(|e| anyhow!("Error serializing transaction: {:?}", e))
    }
}

pub fn export_private(id: &str) -> Result<Vec<u8>> {
    let identity = try_load_single_identity(id)?;
    let serialized = identity.serialize_binary()
        .map_err(|e| anyhow!("There was a problem serializing the identity: {:?}", e))?;
    Ok(serialized)
}

pub fn delete(search: &str, skip_confirm: bool, verbose: bool) -> Result<()> {
    let identities = db::list_local_identities(Some(search))?;
    if identities.len() == 0 {
        Err(anyhow!("No identities match that search"))?;
    }
    let identities = identities.into_iter()
        .map(|x| util::build_identity(&x))
        .collect::<Result<Vec<_>>>()?;
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

pub fn view(search: &str) -> Result<String> {
    let identities = db::list_local_identities(Some(search))?;
    if identities.len() > 1 {
        let identities = identities.iter()
            .map(|x| util::build_identity(x))
            .collect::<Result<Vec<_>>>()?;
        print_identities_table(&identities, false);
        Err(anyhow!("Multiple identities matched that search"))?;
    } else if identities.len() == 0 {
        Err(anyhow!("No identities match that search"))?;
    }
    let transactions = identities[0].clone();
    let identity = util::build_identity(&transactions)?;
    let serialized = identity.serialize_text()
        .map_err(|e| anyhow!("Problem serializing identity: {:?}", e))?;
    Ok(serialized)
}

pub fn fingerprint(id: &str, format: FingerprintFormat) -> Result<String> {
    let transactions = try_load_single_identity(id)?;
    let identity_id = transactions.identity_id()
        .ok_or_else(|| anyhow!("Identity {} not found", id))?;
    let fingerprint = stamp_aux::id::fingerprint(&identity_id)
        .map_err(|e| anyhow!("Problem generating fingerprint: {:?}", e))?;
    match format {
        FingerprintFormat::Svg => {
            Ok(stamp_aux::id::fingerprint_to_svg(&fingerprint))
        }
        FingerprintFormat::Term => {
            let print_char = "██";
            let black = dialoguer::console::Style::new().color256(0);
            let black_block = format!("{}", black.apply_to(print_char));
            let mut out = vec![vec![black_block; 16]; 16];
            for (x, y, rgb) in fingerprint {
                let color_val = rgb_to_256(rgb);
                let color = dialoguer::console::Style::new().color256(color_val);
                let block = format!("{}", color.apply_to(print_char));
                out[y as usize][x as usize] = block;
            }
            Ok(out.into_iter()
                .map(|row| row.join(""))
                .collect::<Vec<_>>()
                .join("\n"))
        }
    }
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

fn rgb_to_256(rgb: [u8; 3]) -> u8 {
    let mapping: [u32; 256] = [
        0x000000, 0x800000, 0x008000, 0x808000,
        0x000080, 0x800080, 0x008080, 0xc0c0c0,
        0x808080, 0xff0000, 0x00ff00, 0xffff00,
        0x0000ff, 0xff00ff, 0x00ffff, 0xffffff,
        0x000000, 0x00005f, 0x000087, 0x0000af,
        0x0000d7, 0x0000ff, 0x005f00, 0x005f5f,
        0x005f87, 0x005faf, 0x005fd7, 0x005fff,
        0x008700, 0x00875f, 0x008787, 0x0087af,
        0x0087d7, 0x0087ff, 0x00af00, 0x00af5f,
        0x00af87, 0x00afaf, 0x00afd7, 0x00afff,
        0x00d700, 0x00d75f, 0x00d787, 0x00d7af,
        0x00d7d7, 0x00d7ff, 0x00ff00, 0x00ff5f,
        0x00ff87, 0x00ffaf, 0x00ffd7, 0x00ffff,
        0x5f0000, 0x5f005f, 0x5f0087, 0x5f00af,
        0x5f00d7, 0x5f00ff, 0x5f5f00, 0x5f5f5f,
        0x5f5f87, 0x5f5faf, 0x5f5fd7, 0x5f5fff,
        0x5f8700, 0x5f875f, 0x5f8787, 0x5f87af,
        0x5f87d7, 0x5f87ff, 0x5faf00, 0x5faf5f,
        0x5faf87, 0x5fafaf, 0x5fafd7, 0x5fafff,
        0x5fd700, 0x5fd75f, 0x5fd787, 0x5fd7af,
        0x5fd7d7, 0x5fd7ff, 0x5fff00, 0x5fff5f,
        0x5fff87, 0x5fffaf, 0x5fffd7, 0x5fffff,
        0x870000, 0x87005f, 0x870087, 0x8700af,
        0x8700d7, 0x8700ff, 0x875f00, 0x875f5f,
        0x875f87, 0x875faf, 0x875fd7, 0x875fff,
        0x878700, 0x87875f, 0x878787, 0x8787af,
        0x8787d7, 0x8787ff, 0x87af00, 0x87af5f,
        0x87af87, 0x87afaf, 0x87afd7, 0x87afff,
        0x87d700, 0x87d75f, 0x87d787, 0x87d7af,
        0x87d7d7, 0x87d7ff, 0x87ff00, 0x87ff5f,
        0x87ff87, 0x87ffaf, 0x87ffd7, 0x87ffff,
        0xaf0000, 0xaf005f, 0xaf0087, 0xaf00af,
        0xaf00d7, 0xaf00ff, 0xaf5f00, 0xaf5f5f,
        0xaf5f87, 0xaf5faf, 0xaf5fd7, 0xaf5fff,
        0xaf8700, 0xaf875f, 0xaf8787, 0xaf87af,
        0xaf87d7, 0xaf87ff, 0xafaf00, 0xafaf5f,
        0xafaf87, 0xafafaf, 0xafafd7, 0xafafff,
        0xafd700, 0xafd75f, 0xafd787, 0xafd7af,
        0xafd7d7, 0xafd7ff, 0xafff00, 0xafff5f,
        0xafff87, 0xafffaf, 0xafffd7, 0xafffff,
        0xd70000, 0xd7005f, 0xd70087, 0xd700af,
        0xd700d7, 0xd700ff, 0xd75f00, 0xd75f5f,
        0xd75f87, 0xd75faf, 0xd75fd7, 0xd75fff,
        0xd78700, 0xd7875f, 0xd78787, 0xd787af,
        0xd787d7, 0xd787ff, 0xd7af00, 0xd7af5f,
        0xd7af87, 0xd7afaf, 0xd7afd7, 0xd7afff,
        0xd7d700, 0xd7d75f, 0xd7d787, 0xd7d7af,
        0xd7d7d7, 0xd7d7ff, 0xd7ff00, 0xd7ff5f,
        0xd7ff87, 0xd7ffaf, 0xd7ffd7, 0xd7ffff,
        0xff0000, 0xff005f, 0xff0087, 0xff00af,
        0xff00d7, 0xff00ff, 0xff5f00, 0xff5f5f,
        0xff5f87, 0xff5faf, 0xff5fd7, 0xff5fff,
        0xff8700, 0xff875f, 0xff8787, 0xff87af,
        0xff87d7, 0xff87ff, 0xffaf00, 0xffaf5f,
        0xffaf87, 0xffafaf, 0xffafd7, 0xffafff,
        0xffd700, 0xffd75f, 0xffd787, 0xffd7af,
        0xffd7d7, 0xffd7ff, 0xffff00, 0xffff5f,
        0xffff87, 0xffffaf, 0xffffd7, 0xffffff,
        0x080808, 0x121212, 0x1c1c1c, 0x262626,
        0x303030, 0x3a3a3a, 0x444444, 0x4e4e4e,
        0x585858, 0x626262, 0x6c6c6c, 0x767676,
        0x808080, 0x8a8a8a, 0x949494, 0x9e9e9e,
        0xa8a8a8, 0xb2b2b2, 0xbcbcbc, 0xc6c6c6,
        0xd0d0d0, 0xdadada, 0xe4e4e4, 0xeeeeee,
    ];

    let mut lowest_dist = (f32::MAX, 0u8);
    fn rgb_dist(rgb1: [u8; 3], rgb2: [u8; 3]) -> f32 {
        // the following color distance routine was taken from here:
        //   https://stackoverflow.com/a/9085524/236331
        // which was lifted from here:
        //   https://www.compuphase.com/cmetric.htm
        // thank you, internet strangers
        let rmean = (rgb1[0] as f32 + rgb2[0] as f32) / 2.0;
        let d_r = rgb1[0] as f32 - rgb2[0] as f32;
        let d_g = rgb1[1] as f32 - rgb2[1] as f32;
        let d_b = rgb1[2] as f32 - rgb2[2] as f32;
        f32::sqrt(
            ((((512.0 + rmean) * d_r * d_r) as i32 >> 8) +
            (4.0 * d_g * d_g) as i32 +
            (((767.0 - rmean) * d_b * d_b) as i32 >> 8)) as f32
        )
    }
    for i in 0..mapping.len() {
        let mapped = mapping[i];
        let r = (mapped >> 16 & 0xff) as u8;
        let g = (mapped >> 8 & 0xff) as u8;
        let b = (mapped & 0xff) as u8;

        let dist = rgb_dist([r, g, b], rgb);
        if dist < lowest_dist.0 {
            lowest_dist = (dist, i as u8)
        }
    }
    lowest_dist.1
}

