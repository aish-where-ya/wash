use std::{fs::File, io::prelude::*, path::PathBuf};

use crate::cli::{extract_keypair, OutputKind};
use anyhow::{anyhow, bail, Context, Result};
use nkeys::KeyPairType;
use provider_archive::ProviderArchive;

const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];

pub struct ParCreateArgs {
    pub capid: String,
    pub vendor: String,
    pub revision: Option<i32>,
    pub version: Option<String>,
    pub schema: Option<PathBuf>,
    pub issuer: Option<String>,
    pub subject: Option<String>,
    pub name: String,
    pub directory: Option<PathBuf>,
    pub arch: String,
    pub binary: String,
    pub destination: Option<String>,
    pub compress: bool,
    pub disable_keygen: bool,
}
pub struct ParInsertArgs {
    pub archive: String,
    pub arch: String,
    pub binary: String,
    pub directory: Option<PathBuf>,
    pub issuer: Option<String>,
    pub subject: Option<String>,
    pub disable_keygen: bool,
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_par_create(
    ParCreateArgs {
        // claims related options
        capid,
        vendor,
        revision,
        version,
        schema,
        issuer,
        subject,
        name,
        // par related options
        directory,
        arch,
        binary,
        destination,
        compress,
        disable_keygen,
    }: ParCreateArgs,
    output_kind: OutputKind,
) -> Result<String> {
    let mut par = ProviderArchive::new(&capid, &name, &vendor, revision, version);

    let mut f = File::open(binary.clone())?;
    let mut lib = Vec::new();
    f.read_to_end(&mut lib)?;

    let issuer = extract_keypair(
        issuer,
        Some(binary.clone()),
        directory.clone(),
        KeyPairType::Account,
        disable_keygen,
        output_kind,
    )?;
    let subject = extract_keypair(
        subject,
        Some(binary.clone()),
        directory,
        KeyPairType::Service,
        disable_keygen,
        output_kind,
    )?;

    par.add_library(&arch, &lib).map_err(convert_error)?;

    let extension = if compress { ".par.gz" } else { ".par" };
    let outfile = match destination {
        Some(path) => path,
        None => format!(
            "{}{}",
            PathBuf::from(binary.clone())
                .file_stem()
                .unwrap()
                .to_str()
                .unwrap(),
            extension
        ),
    };
    if let Some(ref schema) = schema {
        let bytes = std::fs::read(schema)?;
        par.set_schema(
            serde_json::from_slice::<serde_json::Value>(&bytes)
                .with_context(|| "Unable to parse JSON from file contents".to_string())?,
        )
        .map_err(convert_error)
        .with_context(|| format!("Error parsing JSON schema from file '{:?}'", schema))?;
    }

    par.write(&outfile, &issuer, &subject, compress)
        .await
        .map_err(|e| anyhow!("{}", e))
        .with_context(|| {
            format!(
                "Error writing PAR. Please ensure directory {:?} exists",
                PathBuf::from(outfile.clone()).parent().unwrap(),
            )
        })?;
    Ok(outfile)
}

pub async fn handle_par_insert(
    ParInsertArgs {
        archive,
        arch,
        binary,
        directory,
        issuer,
        subject,
        disable_keygen,
    }: ParInsertArgs,
    output_kind: OutputKind,
) -> Result<()> {
    let mut buf = Vec::new();
    let mut f = File::open(archive.clone())?;
    f.read_to_end(&mut buf)?;

    let mut par = ProviderArchive::try_load(&buf)
        .await
        .map_err(convert_error)?;

    let issuer = extract_keypair(
        issuer,
        Some(binary.clone().to_owned()),
        directory.clone(),
        KeyPairType::Account,
        disable_keygen,
        output_kind,
    )?;
    let subject = extract_keypair(
        subject,
        Some(binary.clone().to_owned()),
        directory,
        KeyPairType::Service,
        disable_keygen,
        output_kind,
    )?;

    let mut f = File::open(binary.clone())?;
    let mut lib = Vec::new();
    f.read_to_end(&mut lib)?;

    par.add_library(&arch, &lib).map_err(convert_error)?;

    par.write(&archive, &issuer, &subject, is_compressed(&buf)?)
        .await
        .map_err(convert_error)?;

    Ok(())
}

/// Converts error from Send + Sync error to standard anyhow error
pub(crate) fn convert_error(e: Box<dyn ::std::error::Error + Send + Sync>) -> anyhow::Error {
    anyhow!(e.to_string())
}

/// Inspects the byte slice for a GZIP header, and returns true if the file is compressed
fn is_compressed(input: &[u8]) -> Result<bool> {
    if input.len() < 2 {
        bail!("Not enough bytes to be a valid PAR file");
    }
    Ok(input[0..2] == GZIP_MAGIC)
}
