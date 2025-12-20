//! Ethereum V-App CLI.
//!
//! Command-line interface for interacting with the Ethereum V-App.
//!
//! # Usage
//!
//! ```bash
//! # Connect to native app
//! vnd_ethereum_cli --native
//!
//! # Connect to Speculos emulator
//! vnd_ethereum_cli --sym
//!
//! # Connect to real device via HID
//! vnd_ethereum_cli --hid
//! ```

use clap::{CommandFactory, Parser, Subcommand};
use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::{CmdKind, Highlighter};
use rustyline::hint::Hinter;
use rustyline::validate::{ValidationContext, ValidationResult, Validator};
use rustyline::{Context, Editor, Helper};

use sdk::linewriter::FileLineWriter;
use sdk::vanadium_client::client_utils::{create_default_client, ClientType};

use std::borrow::Cow;

use vnd_ethereum_client::{EthereumClient, EthereumClientError};

mod client;

#[derive(Parser, Debug)]
#[command(name = "vnd-ethereum-cli")]
struct Cli {
    #[clap(subcommand)]
    command: CliCommand,
}

#[derive(Subcommand, Debug)]
#[clap(rename_all = "snake_case")]
enum CliCommand {
    /// Get app configuration and version
    GetConfig,
    /// Get random challenge
    GetChallenge,
    /// Sign a personal message (EIP-191)
    SignMessage {
        #[clap(long)]
        path: String,
        #[clap(long)]
        message: String,
    },
    /// Sign a transaction
    SignTx {
        #[clap(long)]
        path: String,
        #[clap(long)]
        tx_hex: String,
    },
    /// Sign pre-hashed EIP-712 data
    SignEip712 {
        #[clap(long)]
        path: String,
        #[clap(long)]
        domain_hash: String,
        #[clap(long)]
        message_hash: String,
    },
    /// Provide ERC-20 token info
    ProvideToken {
        #[clap(long)]
        chain_id: u64,
        #[clap(long)]
        address: String,
        #[clap(long)]
        ticker: String,
        #[clap(long)]
        decimals: u8,
    },
    /// Set context for metadata lookup
    SetContext {
        #[clap(long)]
        chain_id: u64,
        #[clap(long)]
        address: String,
    },
}

// Command completer for REPL
struct CommandCompleter;

impl CommandCompleter {
    fn get_current_word<'a>(&self, line: &'a str, pos: usize) -> (usize, &'a str) {
        let before = &line[..pos];
        let start = before.rfind(' ').map_or(0, |i| i + 1);
        (&line[start..pos], start).1;
        (start, &line[start..pos])
    }
}

fn make_pair(s: &str) -> Pair {
    Pair {
        display: s.to_string(),
        replacement: s.to_string(),
    }
}

impl Completer for CommandCompleter {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let prefix = line[..pos].trim_start();

        if prefix.is_empty() || !prefix.contains(' ') {
            let suggestions = Cli::command()
                .get_subcommands()
                .filter(|cmd| cmd.get_name().starts_with(prefix))
                .map(|cmd| make_pair(cmd.get_name()))
                .collect();
            return Ok((0, suggestions));
        }

        let subcmd_name = prefix.split_whitespace().next().unwrap();
        if let Some(subcmd) = Cli::command().find_subcommand(subcmd_name) {
            let (start, _) = self.get_current_word(line, pos);

            let Ok(present_args) = shellwords::split(&line[..start].trim_end()) else {
                return Ok((0, vec![]));
            };

            let present_args: Vec<String> = present_args
                .into_iter()
                .map(|arg| arg.split('=').next().unwrap().to_string())
                .collect();

            let suggestions = subcmd
                .get_arguments()
                .filter_map(|arg| arg.get_long().map(|l| l.to_string()))
                .filter(|arg| !present_args.contains(arg))
                .map(|arg| Pair {
                    display: arg.clone(),
                    replacement: arg,
                })
                .collect();
            return Ok((start, suggestions));
        }

        Ok((0, vec![]))
    }
}

impl Validator for CommandCompleter {
    fn validate(
        &self,
        _ctx: &mut ValidationContext<'_>,
    ) -> Result<ValidationResult, ReadlineError> {
        Ok(ValidationResult::Valid(None))
    }
}

impl Highlighter for CommandCompleter {
    fn highlight<'l>(&self, line: &'l str, _pos: usize) -> Cow<'l, str> {
        Cow::Borrowed(line)
    }

    fn highlight_char(&self, _line: &str, _pos: usize, _cmd_kind: CmdKind) -> bool {
        false
    }
}

impl Hinter for CommandCompleter {
    type Hint = String;

    fn hint(&self, _line: &str, _pos: usize, _ctx: &Context<'_>) -> Option<String> {
        None
    }
}

impl Helper for CommandCompleter {}

#[derive(Parser)]
#[command(name = "Vanadium Ethereum", about = "Run the Ethereum V-App on Vanadium")]
struct Args {
    /// Path to the ELF file of the V-App (if not the default one)
    app: Option<String>,

    /// Use the HID interface for a real device
    #[arg(long, group = "interface")]
    hid: bool,

    /// Use Speculos emulator interface
    #[arg(long, group = "interface")]
    sym: bool,

    /// Use the native interface
    #[arg(long, group = "interface")]
    native: bool,
}

fn prepare_prompt_for_clap(line: &str) -> Result<Vec<String>, String> {
    let args = shellwords::split(line).map_err(|e| format!("Failed to parse input: {}", e))?;
    if args.is_empty() {
        return Err("Empty input".to_string());
    }

    let mut clap_args = vec!["dummy".to_string(), args[0].clone()];

    for arg in &args[1..] {
        clap_args.push(format!("--{}", arg));
    }
    Ok(clap_args)
}

fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).map_err(|e| format!("Invalid hex: {}", e))
}

fn parse_hash(s: &str) -> Result<[u8; 32], String> {
    let bytes = parse_hex(s)?;
    if bytes.len() != 32 {
        return Err("Hash must be 32 bytes".to_string());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn parse_address(s: &str) -> Result<[u8; 20], String> {
    let bytes = parse_hex(s)?;
    if bytes.len() != 20 {
        return Err("Address must be 20 bytes".to_string());
    }
    let mut arr = [0u8; 20];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

async fn handle_cli_command(
    ethereum_client: &mut EthereumClient,
    cli: &Cli,
) -> Result<(), EthereumClientError> {
    match &cli.command {
        CliCommand::GetConfig => {
            let config = ethereum_client.get_app_configuration().await?;
            println!(
                "Version: {}.{}.{}",
                config.version_major, config.version_minor, config.version_patch
            );
            println!("Blind signing: {}", config.blind_signing_enabled);
            println!("EIP-712 filtering: {}", config.eip712_filtering_enabled);
        }
        CliCommand::GetChallenge => {
            let challenge = ethereum_client.get_challenge().await?;
            println!("Challenge: 0x{}", hex::encode(challenge));
        }
        CliCommand::SignMessage { path, message } => {
            let path = client::parse_derivation_path(path)?;
            let sig = ethereum_client
                .sign_personal_message(&path, message.as_bytes())
                .await?;
            println!("v: {}", sig.v);
            println!("r: 0x{}", hex::encode(sig.r));
            println!("s: 0x{}", hex::encode(sig.s));
        }
        CliCommand::SignTx { path, tx_hex } => {
            let path = client::parse_derivation_path(path)?;
            let tx_data = parse_hex(tx_hex)?;
            let sig = ethereum_client.sign_transaction(&path, &tx_data).await?;
            println!("v: {}", sig.v);
            println!("r: 0x{}", hex::encode(sig.r));
            println!("s: 0x{}", hex::encode(sig.s));
        }
        CliCommand::SignEip712 {
            path,
            domain_hash,
            message_hash,
        } => {
            let path = client::parse_derivation_path(path)?;
            let domain = parse_hash(domain_hash)?;
            let message = parse_hash(message_hash)?;
            let sig = ethereum_client
                .sign_eip712_hashed(&path, &domain, &message)
                .await?;
            println!("v: {}", sig.v);
            println!("r: 0x{}", hex::encode(sig.r));
            println!("s: 0x{}", hex::encode(sig.s));
        }
        CliCommand::ProvideToken {
            chain_id,
            address,
            ticker,
            decimals,
        } => {
            let addr = parse_address(address)?;
            let info = common::types::TokenInfo {
                chain_id: *chain_id,
                address: addr,
                ticker: ticker.clone(),
                decimals: *decimals,
            };
            let accepted = ethereum_client
                .provide_erc20_token_info(info, vec![])
                .await?;
            println!("Accepted: {}", accepted);
        }
        CliCommand::SetContext { chain_id, address } => {
            let addr = parse_address(address)?;
            let bound = ethereum_client
                .by_contract_address_and_chain(*chain_id, addr)
                .await?;
            println!("Context bound: {}", bound);
        }
    }
    Ok(())
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "debug")]
    {
        let log_file = std::fs::File::create("debug.log")?;
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
            .target(env_logger::Target::Pipe(Box::new(log_file)))
            .init();
    }

    let args = Args::parse();

    let client_type = if args.hid {
        ClientType::Hid
    } else if args.native {
        ClientType::Native
    } else if args.sym {
        ClientType::Tcp
    } else {
        ClientType::Any
    };

    let print_writer = Box::new(FileLineWriter::new("print.log", true, true));
    let mut ethereum_client = EthereumClient::new(
        create_default_client("vnd-ethereum", client_type, Some(print_writer)).await?,
    );

    let mut rl = Editor::<CommandCompleter, rustyline::history::DefaultHistory>::new()?;
    rl.set_helper(Some(CommandCompleter));

    let _ = rl.load_history("eth_history.txt");

    let mut with_unrecoverable_error = false;
    loop {
        match rl.readline("ETH> ") {
            Ok(line) => {
                if line.trim().is_empty() {
                    continue;
                }

                if line.trim() == "exit" {
                    println!("Exiting");
                    break;
                }

                rl.add_history_entry(line.as_str())?;

                let clap_args = match prepare_prompt_for_clap(&line) {
                    Ok(args) => args,
                    Err(e) => {
                        println!("Error: {}", e);
                        continue;
                    }
                };

                match Cli::try_parse_from(clap_args) {
                    Ok(cli) => match handle_cli_command(&mut ethereum_client, &cli).await {
                        Ok(_) => {}
                        Err(EthereumClientError::AppError(e)) => {
                            println!("V-App error: {}", e);
                        }
                        Err(e) => {
                            println!("Fatal error: {}", e);
                            with_unrecoverable_error = true;
                            break;
                        }
                    },
                    Err(e) => println!("Invalid command: {}", e),
                }
            }
            Err(ReadlineError::Interrupted) => println!("Interrupted"),
            Err(ReadlineError::Eof) => {
                println!("Exiting");
                break;
            }
            Err(err) => {
                println!("Error reading line: {:?}", err);
                continue;
            }
        }
    }

    rl.save_history("eth_history.txt")?;

    if !with_unrecoverable_error {
        let exit_status = ethereum_client.exit().await?;
        if exit_status != 0 {
            println!("V-App exited with status: {}", exit_status);
        }
    }

    Ok(())
}
