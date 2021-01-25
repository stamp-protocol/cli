use crate::{
    util,
};
use stamp_core::{
    identity::VersionedIdentity,
};
use std::{
    convert::TryFrom,
    fs::{self, File},
    io::{
        prelude::*,
        BufReader,
    },
    path::{Path, PathBuf},
};

fn data_dir() -> Result<PathBuf, String> {
    util::data_dir()
}

fn data_dir_id() -> Result<PathBuf, String> {
    let mut dir = data_dir()?;
    dir.push("identities");
    Ok(dir)
}

pub(crate) fn save_identity<T: Into<VersionedIdentity>>(identity: T) -> Result<PathBuf, String> {
    let data_dir = data_dir_id()?;
    fs::create_dir_all(&data_dir)
        .map_err(|e| format!("Cannot create data directory: {:?}", e))?;
    let versioned = identity.into();
    let id = id_str!(versioned.id())?;
    let serialized = versioned.serialize_binary()
        .map_err(|e| format!("Error serializing identity: {:?}", e))?;
    let mut filename = data_dir.clone();
    filename.push(id);
    let mut handle = File::create(&filename)
        .map_err(|e| format!("Error opening identity file: {}: {:?}", filename.to_string_lossy(), e))?;
    handle.write_all(serialized.as_slice())
        .map_err(|e| format!("Error writing to identity file: {}: {:?}", filename.to_string_lossy(), e))?;
    Ok(filename)
}

/// Load an identity by ID.
pub(crate) fn load_identity<T: AsRef<Path>>(id: T) -> Result<Option<VersionedIdentity>, String> {
    let data_dir = data_dir_id()?;
    let mut filename = data_dir.clone();
    filename.push(id);
    let file = File::open(&filename)
        .map_err(|e| format!("Unable to open identity file: {}: {:?}", filename.to_string_lossy(), e))?;
    let mut reader = BufReader::new(file);
    let mut contents = Vec::new();
    reader.read_to_end(&mut contents)
        .map_err(|e| format!("Problem reading identity file: {}: {:?}", filename.to_string_lossy(), e))?;
    let identity = VersionedIdentity::deserialize_binary(contents.as_slice())
        .map_err(|e| format!("Problem deserializing identity: {}: {:?}", filename.to_string_lossy(), e))?;
    Ok(Some(identity))
}

/// Load an identity by ID.
pub(crate) fn load_identities_by_prefix<T: AsRef<Path>>(id_prefix: T) -> Result<Vec<VersionedIdentity>, String> {
    let data_dir = data_dir_id()?;
    let mut filename = data_dir.clone();
    filename.push(format!("{}*", id_prefix.as_ref().to_string_lossy()));

    let mut identities = Vec::new();
    let entries = glob::glob(&filename.to_string_lossy())
        .map_err(|e| format!("Problem reading identity files: {:?}", e))?;
    for entry in entries {
        match entry {
            Ok(path) => {
                if !path.is_file() { continue; }
                let identity = load_identity(path.file_name().unwrap_or("".as_ref()))?;
                if let Some(identity) = identity {
                    identities.push(identity);
                }
            }
            Err(e) => Err(format!("Problem reading identity files: {:?}", e))?,
        }
    }
    Ok(identities)
}

/// List identities stored locally.
pub(crate) fn list_local_identities(search: Option<&str>) -> Result<Vec<VersionedIdentity>, String> {
    let dir = data_dir_id()?;
    let mut identities = Vec::new();
    if dir.is_dir() {
        let entries = fs::read_dir(&dir)
            .map_err(|e| format!("Cannot read directory: {}: {:?}", dir.to_string_lossy(), e))?;
        for entry in entries {
            match entry {
                Ok(entry) => {
                    if !entry.path().is_file() { continue; }
                    if let Some(identity) = load_identity(entry.file_name())? {
                        if let Some(filter_str) = search {
                            let id_full = id_str!(identity.id())?;
                            let nickname = identity.nickname_maybe().unwrap_or(String::from(""));
                            let emails = identity.emails();
                            let names = identity.names();
                            let filter = &filter_str.to_lowercase();
                            if !(id_full.to_lowercase().contains(filter) ||
                                 nickname.to_lowercase().contains(filter) ||
                                 names.iter().filter(|x| x.contains(filter)).count() > 0 ||
                                 emails.iter().filter(|x| x.contains(filter)).count() > 0) {
                                continue;
                            }
                        }
                        identities.push(identity);
                    }
                }
                _ => {}
            }
        }
    }
    Ok(identities)
}

/// Delete a local identity by id.
pub(crate) fn delete_identity<T: AsRef<Path>>(id: T, permanent: bool) -> Result<(), String> {
    let dir = data_dir_id()?;
    let mut filename = dir.clone();
    filename.push(&id);
    if permanent {
        fs::remove_file(&filename)
            .map_err(|e| format!("Error deleting file: {}: {:?}", filename.to_string_lossy(), e))?;
    } else {
        let mut trash = dir.clone();
        trash.push("trash");    // I'M THE TRAAAAASH MAN
        fs::create_dir_all(&trash)
            .map_err(|e| format!("Cannot create trash directory: {:?}", e))?;
        trash.push(&id);
        fs::rename(filename, trash)
            .map_err(|e| format!("Error moving identity to trash: {:?}", e))?;
    }
    Ok(())
}

