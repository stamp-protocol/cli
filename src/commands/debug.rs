use crate::{
    commands::id,
    db,
};

pub fn resave(id: &str) -> Result<(), String> {
    let identity = id::try_load_single_identity(id)?;
    db::save_identity(identity)?;
    println!("Identity re-saved");
    Ok(())
}

