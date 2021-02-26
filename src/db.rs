use crate::{
    util,
};
use rusqlite::{params, Connection};
use stamp_core::{
    dag::Transactions,
    identity::IdentityID,
    util::SerdeBinary,
};
use std::convert::TryFrom;
use std::fs;

fn conn() -> Result<Connection, String> {
    let dir = util::data_dir()?;
    fs::create_dir_all(&dir)
        .map_err(|e| format!("Cannot create data directory: {:?}", e))?;
    let mut db_file = dir.clone();
    db_file.push("db.sqlite");
    let flags =
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE |
        rusqlite::OpenFlags::SQLITE_OPEN_CREATE |
        rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = Connection::open_with_flags(&db_file, flags)
        .map_err(|e| format!("There was a problem loading the identity database: {}: {:?}", db_file.to_string_lossy(), e))?;
    Ok(conn)
}

pub fn ensure_schema() -> Result<(), String> {
    let conn = conn()?;
    conn.execute("CREATE TABLE IF NOT EXISTS identities (id TEXT PRIMARY KEY, nickname TEXT, created TEXT NOT NULL, data BLOB NOT NULL, name_lookup JSON, email_lookup JSON, claim_lookup JSON, stamp_lookup JSON)", params![])
        .map_err(|e| format!("Error initializing database: {:?}", e))?;
    Ok(())
}

fn json_arr(vec: &Vec<String>) -> String {
    format!(r#"["{}"]"#, vec.join(r#"",""#))
}

pub fn save_identity(transactions: Transactions) -> Result<(), String> {
    let identity = transactions.build_identity()
        .map_err(|e| format!("problem building identity: {}", e))?;
    let id_str = id_str!(identity.id())?;
    let nickname = identity.nickname_maybe();
    let created = format!("{}", identity.created().format("%+"));

    let name_lookup = identity.names();
    let email_lookup = identity.emails();
    let claim_lookup = identity.claims().iter()
        .map(|x| id_str!(x.claim().id()))
        .collect::<Result<Vec<String>, String>>()
        .map_err(|e| format!("Error grabbing claims for indexing: {:?}", e))?;
    let stamp_lookup = identity.claims().iter()
        .map(|x| {
            x.stamps().iter().map(|x| { id_str!(x.id()) })
        })
        .flatten()
        .collect::<Result<Vec<String>, String>>()
        .map_err(|e| format!("Error grabbing stamps for indexing: {:?}", e))?;

    let serialized = transactions.serialize_binary()
        .map_err(|e| format!("problem serializing identity {}", e))?;
    let conn = conn()?;
    conn.execute("BEGIN", params![]).map_err(|e| format!("Error saving identity: {:?}", e))?;
    conn.execute("DELETE FROM identities WHERE id = ?1", params![id_str])
        .map_err(|e| format!("Error saving identity: {:?}", e))?;
    conn.execute(
        r#"
            INSERT INTO identities
            (id, nickname, created, data, name_lookup, email_lookup, claim_lookup, stamp_lookup)
            VALUES (?1, ?2, ?3, ?4, json(?5), json(?6), json(?7), json(?8))
        "#,
        params![
            id_str,
            nickname,
            created,
            serialized,
            json_arr(&name_lookup),
            json_arr(&email_lookup),
            json_arr(&claim_lookup),
            json_arr(&stamp_lookup),
        ]
    ).map_err(|e| format!("Error saving identity: {:?}", e))?;
    conn.execute("COMMIT", params![]).map_err(|e| format!("Error saving identity: {:?}", e))?;
    Ok(())
}

/// Load an identity by ID.
pub fn load_identity(id: &IdentityID) -> Result<Option<Transactions>, String> {
    let conn = conn()?;
    let id_str = id_str!(id)?;
    let qry_res = conn.query_row(
        "SELECT data FROM identities WHERE id = ?1 ORDER BY created ASC",
        params![id_str],
        |row| row.get(0)
    );
    let blob: Option<Vec<u8>> = match qry_res {
        Ok(blob) => Some(blob),
        Err(rusqlite::Error::QueryReturnedNoRows) => None,
        Err(e) => Err(format!("Error loading identity: {:?}", e))?,
    };
    match blob {
        Some(data) => {
            let transactions = Transactions::deserialize_binary(data.as_slice())
                .map_err(|e| format!("Problem deserializing identity: {:?}", e))?;
            Ok(Some(transactions))
        }
        None => Ok(None),
    }
}

/// Load an identity by ID.
pub fn load_identities_by_prefix(id_prefix: &str) -> Result<Vec<Transactions>, String> {
    let conn = conn()?;
    let mut stmt = conn.prepare("SELECT data FROM identities WHERE id like ?1 ORDER BY created ASC")
        .map_err(|e| format!("Error loading identities: {:?}", e))?;
    let rows = stmt.query_map(params![format!("{}%", id_prefix)], |row| row.get(0))
        .map_err(|e| format!("Error loading identities: {:?}", e))?;
    let mut identities = Vec::new();
    for data in rows {
        let data_bin: Vec<u8> = data.map_err(|e| format!("Error loading identity: {:?}", e))?;
        let deserialized = Transactions::deserialize_binary(&data_bin)
            .map_err(|e| format!("Error deserializing identity: {:?}", e))?;
        identities.push(deserialized);
    }
    Ok(identities)
}

/// List identities stored locally.
pub fn list_local_identities(search: Option<&str>) -> Result<Vec<Transactions>, String> {
    let conn = conn()?;
    let qry = if search.is_some() {
        r#"
            SELECT DISTINCT
                i.id, i.data
            FROM
                identities i,
                json_each(i.name_lookup) jnl,
                json_each(i.email_lookup) jel,
                json_each(i.claim_lookup) jcl,
                json_each(i.stamp_lookup) jsl
            WHERE
                i.id LIKE ?1 OR
                jnl.value LIKE ?1 OR
                jel.value LIKE ?1 OR
                jcl.value LIKE ?1 OR
                jsl.value LIKE ?1
            ORDER BY
                i.created ASC
        "#
    } else {
        r#"SELECT i.id, i.data FROM identities i ORDER BY i.created ASC"#
    };

    let mut stmt = conn.prepare(qry)
        .map_err(|e| format!("Error loading identities: {:?}", e))?;
    let row_mapper = |row: &rusqlite::Row<'_>| -> rusqlite::Result<_> { row.get(1) };
    let rows = if let Some(search) = search {
        let finder = format!("%{}%", search);
        stmt.query_map(params![finder], row_mapper)
            .map_err(|e| format!("Error loading identities: {:?}", e))?
    } else {
        stmt.query_map(params![], row_mapper)
            .map_err(|e| format!("Error loading identities: {:?}", e))?
    };
    let mut identities = Vec::new();
    for data in rows {
        let data_bin: Vec<u8> = data.map_err(|e| format!("Error loading identity: {:?}", e))?;
        let deserialized = Transactions::deserialize_binary(&data_bin)
            .map_err(|e| format!("Error deserializing identity: {:?}", e))?;
        identities.push(deserialized);
    }
    Ok(identities)
}

pub fn find_identity_by_prefix(ty: &str, id_prefix: &str) -> Result<Option<Transactions>, String> {
    let conn = conn()?;
    let qry = format!(r#"
        SELECT DISTINCT
            i.id, i.data
        FROM
            identities i,
            json_each(i.{}_lookup) jcl
        WHERE
            jcl.value LIKE ?1
        ORDER BY
            i.created ASC
    "#, ty);

    let finder = format!("{}%", id_prefix);
    let qry_res = conn.query_row(
        &qry,
        params![finder],
        |row| row.get(1)
    );
    let blob: Option<Vec<u8>> = match qry_res {
        Ok(blob) => Some(blob),
        Err(rusqlite::Error::QueryReturnedNoRows) => None,
        Err(e) => Err(format!("Error loading identity: {:?}", e))?,
    };
    match blob {
        Some(data) => {
            let transactions = Transactions::deserialize_binary(data.as_slice())
                .map_err(|e| format!("Problem deserializing identity: {:?}", e))?;
            Ok(Some(transactions))
        }
        None => Ok(None),
    }
}

/// Delete a local identity by id.
pub fn delete_identity(id: &str) -> Result<(), String> {
    let conn = conn()?;
    conn.execute("BEGIN", params![]).map_err(|e| format!("Error deleting identity: {:?}", e))?;
    conn.execute("DELETE FROM identities WHERE id = ?1", params![id])
        .map_err(|e| format!("Error deleting identity: {:?}", e))?;
    conn.execute("COMMIT", params![]).map_err(|e| format!("Error deleting identity: {:?}", e))?;
    Ok(())
}

