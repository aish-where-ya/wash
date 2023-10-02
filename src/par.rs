use std::{collections::HashMap, path::PathBuf};

use anyhow::Result;
use clap::{Parser, Subcommand};
use log::warn;
use serde_json::json;
use wash_lib::cli::par::{handle_par_create, handle_par_insert};
use wash_lib::cli::{inspect, par, CommandOutput, OutputKind};

#[derive(Debug, Clone, Subcommand)]
pub(crate) enum ParCliCommand {
    /// Build a provider archive file
    #[clap(name = "create")]
    Create(CreateCommand),
    /// Inspect a provider archive file
    #[clap(name = "inspect")]
    Inspect(InspectCommand),
    /// Insert a provider into a provider archive file
    #[clap(name = "insert")]
    Insert(InsertCommand),
}

#[derive(Parser, Debug, Clone)]
pub(crate) struct CreateCommand {
    /// Capability contract ID (e.g. wasmcloud:messaging or wasmcloud:keyvalue).
    #[clap(short = 'c', long = "capid")]
    capid: String,

    /// Vendor string to help identify the publisher of the provider (e.g. Redis, Cassandra, wasmcloud, etc). Not unique.
    #[clap(short = 'v', long = "vendor")]
    vendor: String,

    /// Monotonically increasing revision number
    #[clap(short = 'r', long = "revision")]
    revision: Option<i32>,

    /// Human friendly version string
    #[clap(long = "version")]
    version: Option<String>,

    /// Optional path to a JSON schema describing the link definition specification for this provider.
    #[clap(
        short = 'j',
        long = "schema",
        env = "WASH_JSON_SCHEMA",
        hide_env_values = true
    )]
    schema: Option<PathBuf>,

    /// Location of key files for signing. Defaults to $WASH_KEYS ($HOME/.wash/keys)
    #[clap(
        short = 'd',
        long = "directory",
        env = "WASH_KEYS",
        hide_env_values = true
    )]
    directory: Option<PathBuf>,

    /// Path to issuer seed key (account). If this flag is not provided, the will be sourced from $WASH_KEYS ($HOME/.wash/keys) or generated for you if it cannot be found.
    #[clap(
        short = 'i',
        long = "issuer",
        env = "WASH_ISSUER_KEY",
        hide_env_values = true
    )]
    issuer: Option<String>,

    /// Path to subject seed key (service). If this flag is not provided, the will be sourced from $WASH_KEYS ($HOME/.wash/keys) or generated for you if it cannot be found.
    #[clap(
        short = 's',
        long = "subject",
        env = "WASH_SUBJECT_KEY",
        hide_env_values = true
    )]
    subject: Option<String>,

    /// Name of the capability provider
    #[clap(short = 'n', long = "name")]
    name: String,

    /// Architecture of provider binary in format ARCH-OS (e.g. x86_64-linux)
    #[clap(short = 'a', long = "arch")]
    arch: String,

    /// Path to provider binary for populating the archive
    #[clap(short = 'b', long = "binary")]
    binary: String,

    /// File output destination path
    #[clap(long = "destination")]
    destination: Option<String>,

    /// Include a compressed provider archive
    #[clap(long = "compress")]
    compress: bool,

    /// Disables autogeneration of signing keys
    #[clap(long = "disable-keygen")]
    disable_keygen: bool,
}

#[derive(Parser, Debug, Clone)]
pub(crate) struct InspectCommand {
    /// Path to provider archive or OCI URL of provider archive
    #[clap(name = "archive")]
    archive: String,

    /// Digest to verify artifact against (if OCI URL is provided for <archive>)
    #[clap(short = 'd', long = "digest")]
    digest: Option<String>,

    /// Allow latest artifact tags (if OCI URL is provided for <archive>)
    #[clap(long = "allow-latest")]
    allow_latest: bool,

    /// OCI username, if omitted anonymous authentication will be used
    #[clap(
        short = 'u',
        long = "user",
        env = "WASH_REG_USER",
        hide_env_values = true
    )]
    user: Option<String>,

    /// OCI password, if omitted anonymous authentication will be used
    #[clap(
        short = 'p',
        long = "password",
        env = "WASH_REG_PASSWORD",
        hide_env_values = true
    )]
    password: Option<String>,

    /// Allow insecure (HTTP) registry connections
    #[clap(long = "insecure")]
    insecure: bool,

    /// skip the local OCI cache
    #[clap(long = "no-cache")]
    no_cache: bool,
}

#[derive(Parser, Debug, Clone)]
pub(crate) struct InsertCommand {
    /// Path to provider archive
    #[clap(name = "archive")]
    archive: String,

    /// Architecture of binary in format ARCH-OS (e.g. x86_64-linux)
    #[clap(short = 'a', long = "arch")]
    arch: String,

    /// Path to provider binary to insert into archive
    #[clap(short = 'b', long = "binary")]
    binary: String,

    /// Location of key files for signing. Defaults to $WASH_KEYS ($HOME/.wash/keys)
    #[clap(
        short = 'd',
        long = "directory",
        env = "WASH_KEYS",
        hide_env_values = true
    )]
    directory: Option<PathBuf>,

    /// Path to issuer seed key (account). If this flag is not provided, the will be sourced from $WASH_KEYS ($HOME/.wash/keys) or generated for you if it cannot be found.
    #[clap(
        short = 'i',
        long = "issuer",
        env = "WASH_ISSUER_KEY",
        hide_env_values = true
    )]
    issuer: Option<String>,

    /// Path to subject seed key (service). If this flag is not provided, the will be sourced from $WASH_KEYS ($HOME/.wash/keys) or generated for you if it cannot be found.
    #[clap(
        short = 's',
        long = "subject",
        env = "WASH_SUBJECT_KEY",
        hide_env_values = true
    )]
    subject: Option<String>,

    /// Disables autogeneration of signing keys
    #[clap(long = "disable-keygen")]
    disable_keygen: bool,
}

impl From<InspectCommand> for inspect::InspectCliCommand {
    fn from(cmd: InspectCommand) -> Self {
        inspect::InspectCliCommand {
            target: cmd.archive,
            jwt_only: false,
            digest: cmd.digest,
            allow_latest: cmd.allow_latest,
            user: cmd.user,
            password: cmd.password,
            insecure: cmd.insecure,
            no_cache: cmd.no_cache,
        }
    }
}

impl From<CreateCommand> for par::ParCreateArgs {
    fn from(cmd: CreateCommand) -> Self {
        par::ParCreateArgs {
            capid: cmd.capid,
            vendor: cmd.vendor,
            revision: cmd.revision,
            version: cmd.version,
            schema: cmd.schema,
            issuer: cmd.issuer,
            subject: cmd.subject,
            name: cmd.name,
            directory: cmd.directory,
            arch: cmd.arch,
            binary: cmd.binary,
            destination: cmd.destination,
            compress: cmd.compress,
            disable_keygen: cmd.disable_keygen,
        }
    }
}

impl From<InsertCommand> for par::ParInsertArgs {
    fn from(cmd: InsertCommand) -> Self {
        par::ParInsertArgs {
            archive: cmd.archive,
            arch: cmd.arch,
            binary: cmd.binary,
            directory: cmd.directory,
            issuer: cmd.issuer,
            subject: cmd.subject,
            disable_keygen: cmd.disable_keygen,
        }
    }
}

pub(crate) async fn handle_command(
    command: ParCliCommand,
    output_kind: OutputKind,
) -> Result<CommandOutput> {
    match command {
        ParCliCommand::Create(cmd) => handle_create(cmd, output_kind).await,
        ParCliCommand::Inspect(cmd) => {
            warn!("par inspect will be deprecated in future versions. Use inspect instead.");
            inspect::handle_command(cmd, output_kind).await
        }
        ParCliCommand::Insert(cmd) => handle_insert(cmd, output_kind).await,
    }
}

/// Creates a provider archive using an initial architecture target, provider, and signing keys
pub(crate) async fn handle_create(
    cmd: CreateCommand,
    output_kind: OutputKind,
) -> Result<CommandOutput> {
    let outfile = handle_par_create(cmd.into(), output_kind).await?;

    let mut map = HashMap::new();
    map.insert("file".to_string(), json!(outfile));
    Ok(CommandOutput::new(
        format!("Successfully created archive {outfile}"),
        map,
    ))
}

/// Loads a provider archive and attempts to insert an additional provider into it
pub(crate) async fn handle_insert(
    cmd: InsertCommand,
    output_kind: OutputKind,
) -> Result<CommandOutput> {
    handle_par_insert(cmd.clone().into(), output_kind).await?;

    let mut map = HashMap::new();
    map.insert("file".to_string(), json!(cmd.archive));
    Ok(CommandOutput::new(
        format!(
            "Successfully inserted {} into archive {}",
            cmd.binary, cmd.archive
        ),
        map,
    ))
}

#[cfg(test)]
mod test {
    use super::*;

    #[derive(Parser, Debug)]
    struct Cmd {
        #[clap(subcommand)]
        par: ParCliCommand,
    }

    // Uses all flags and options of the `par create` command
    // to ensure API does not change between versions
    #[test]
    fn test_par_create_comprehensive() {
        const ISSUER: &str = "SAAJLQZDZO57THPTIIEELEY7FJYOJZQWQD7FF4J67TUYTSCOXTF7R4Y3VY";
        const SUBJECT: &str = "SVAH7IN6QE6XODCGIIWZQDZ5LNSSS4FNEO6SNHZSSASW4BBBKSZ6KWTKWY";
        let create_long: Cmd = clap::Parser::try_parse_from([
            "par",
            "create",
            "--arch",
            "x86_64-testrunner",
            "--binary",
            "./testrunner.so",
            "--capid",
            "wasmcloud:test",
            "--name",
            "CreateTest",
            "--vendor",
            "TestRunner",
            "--destination",
            "./test.par.gz",
            "--revision",
            "1",
            "--version",
            "1.11.111",
            "--directory",
            "./tests/fixtures",
            "--issuer",
            ISSUER,
            "--subject",
            SUBJECT,
            "--disable-keygen",
            "--compress",
        ])
        .unwrap();
        match create_long.par {
            ParCliCommand::Create(CreateCommand {
                capid,
                vendor,
                revision,
                version,
                schema,
                directory,
                issuer,
                subject,
                name,
                arch,
                binary,
                destination,
                compress,
                disable_keygen,
            }) => {
                assert_eq!(capid, "wasmcloud:test");
                assert_eq!(arch, "x86_64-testrunner");
                assert_eq!(binary, "./testrunner.so");
                assert_eq!(directory.unwrap(), PathBuf::from("./tests/fixtures"));
                assert_eq!(issuer.unwrap(), ISSUER);
                assert_eq!(subject.unwrap(), SUBJECT);
                assert_eq!(name, "CreateTest");
                assert_eq!(vendor, "TestRunner");
                assert_eq!(destination.unwrap(), "./test.par.gz");
                assert_eq!(revision.unwrap(), 1);
                assert_eq!(version.unwrap(), "1.11.111");
                assert_eq!(schema, None);
                assert!(disable_keygen);
                assert!(compress);
            }
            cmd => panic!("par insert constructed incorrect command {cmd:?}"),
        }
        let create_short: Cmd = clap::Parser::try_parse_from([
            "par",
            "create",
            "-a",
            "x86_64-testrunner",
            "-b",
            "./testrunner.so",
            "-c",
            "wasmcloud:test",
            "-n",
            "CreateTest",
            "-v",
            "TestRunner",
            "--destination",
            "./test.par.gz",
            "-r",
            "1",
            "--version",
            "1.11.111",
            "-d",
            "./tests/fixtures",
            "-i",
            ISSUER,
            "-s",
            SUBJECT,
        ])
        .unwrap();
        match create_short.par {
            ParCliCommand::Create(CreateCommand {
                capid,
                vendor,
                revision,
                version,
                schema,
                directory,
                issuer,
                subject,
                name,
                arch,
                binary,
                destination,
                compress,
                disable_keygen,
            }) => {
                assert_eq!(capid, "wasmcloud:test");
                assert_eq!(arch, "x86_64-testrunner");
                assert_eq!(binary, "./testrunner.so");
                assert_eq!(directory.unwrap(), PathBuf::from("./tests/fixtures"));
                assert_eq!(issuer.unwrap(), ISSUER);
                assert_eq!(subject.unwrap(), SUBJECT);
                assert_eq!(name, "CreateTest");
                assert_eq!(vendor, "TestRunner");
                assert_eq!(destination.unwrap(), "./test.par.gz");
                assert_eq!(revision.unwrap(), 1);
                assert_eq!(version.unwrap(), "1.11.111");
                assert_eq!(schema, None);
                assert!(!disable_keygen);
                assert!(!compress);
            }
            cmd => panic!("par insert constructed incorrect command {cmd:?}"),
        }
    }

    // Uses all flags and options of the `par insert` command
    // to ensure API does not change between versions
    #[test]
    fn test_par_insert_comprehensive() {
        const ISSUER: &str = "SAAJLQZDZO57THPTQLEELEY7FJYOJZQWQD7FF4J67TUYTSCOXTF7R4Y3VY";
        const SUBJECT: &str = "SVAH7IN6QE6XODCGQAWZQDZ5LNSSS4FNEO6SNHZSSASW4BBBKSZ6KWTKWY";
        let insert_short: Cmd = clap::Parser::try_parse_from([
            "par",
            "insert",
            "libtest.par.gz",
            "-a",
            "x86_64-testrunner",
            "-b",
            "./testrunner.so",
            "-d",
            "./tests/fixtures",
            "-i",
            ISSUER,
            "-s",
            SUBJECT,
            "--disable-keygen",
        ])
        .unwrap();
        match insert_short.par {
            ParCliCommand::Insert(InsertCommand {
                archive,
                arch,
                binary,
                directory,
                issuer,
                subject,
                disable_keygen,
            }) => {
                assert_eq!(archive, "libtest.par.gz");
                assert_eq!(arch, "x86_64-testrunner");
                assert_eq!(binary, "./testrunner.so");
                assert_eq!(directory.unwrap(), PathBuf::from("./tests/fixtures"));
                assert_eq!(issuer.unwrap(), ISSUER);
                assert_eq!(subject.unwrap(), SUBJECT);
                assert!(disable_keygen);
            }
            cmd => panic!("par insert constructed incorrect command {cmd:?}"),
        }
        let insert_long: Cmd = clap::Parser::try_parse_from([
            "par",
            "insert",
            "libtest.par.gz",
            "--arch",
            "x86_64-testrunner",
            "--binary",
            "./testrunner.so",
            "--directory",
            "./tests/fixtures",
            "--issuer",
            ISSUER,
            "--subject",
            SUBJECT,
        ])
        .unwrap();
        match insert_long.par {
            ParCliCommand::Insert(InsertCommand {
                archive,
                arch,
                binary,
                directory,
                issuer,
                subject,
                disable_keygen,
            }) => {
                assert_eq!(archive, "libtest.par.gz");
                assert_eq!(arch, "x86_64-testrunner");
                assert_eq!(binary, "./testrunner.so");
                assert_eq!(directory.unwrap(), PathBuf::from("./tests/fixtures"));
                assert_eq!(issuer.unwrap(), ISSUER);
                assert_eq!(subject.unwrap(), SUBJECT);
                assert!(!disable_keygen);
            }
            cmd => panic!("par insert constructed incorrect command {cmd:?}"),
        }
    }

    // Uses all flags and options of the `par inspect` command
    // to ensure API does not change between versions
    #[test]
    fn test_par_inspect_comprehensive() {
        const LOCAL: &str = "./coolthing.par.gz";
        const REMOTE: &str = "wasmcloud.azurecr.io/coolthing.par.gz";

        let inspect_long: Cmd = clap::Parser::try_parse_from([
            "par",
            "inspect",
            LOCAL,
            "--digest",
            "sha256:blah",
            "--password",
            "secret",
            "--user",
            "name",
            "--no-cache",
        ])
        .unwrap();
        match inspect_long.par {
            ParCliCommand::Inspect(InspectCommand {
                archive,
                digest,
                allow_latest,
                user,
                password,
                insecure,
                no_cache,
            }) => {
                assert_eq!(archive, LOCAL);
                assert_eq!(digest.unwrap(), "sha256:blah");
                assert!(!allow_latest);
                assert!(!insecure);
                assert_eq!(user.unwrap(), "name");
                assert_eq!(password.unwrap(), "secret");
                assert!(no_cache);
            }
            cmd => panic!("par inspect constructed incorrect command {cmd:?}"),
        }
        let inspect_short: Cmd = clap::Parser::try_parse_from([
            "par",
            "inspect",
            REMOTE,
            "-d",
            "sha256:blah",
            "-p",
            "secret",
            "-u",
            "name",
            "--allow-latest",
            "--insecure",
            "--no-cache",
        ])
        .unwrap();
        match inspect_short.par {
            ParCliCommand::Inspect(InspectCommand {
                archive,
                digest,
                allow_latest,
                user,
                password,
                insecure,
                no_cache,
            }) => {
                assert_eq!(archive, REMOTE);
                assert_eq!(digest.unwrap(), "sha256:blah");
                assert!(allow_latest);
                assert!(insecure);
                assert_eq!(user.unwrap(), "name");
                assert_eq!(password.unwrap(), "secret");
                assert!(no_cache);
            }
            cmd => panic!("par inspect constructed incorrect command {cmd:?}"),
        }
    }
}
