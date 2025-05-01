// client/src/main.rs
use clap::{App, Arg, SubCommand};
use log::{debug, info, warn, LevelFilter};
use simplelog::{ColorChoice, Config as SimplelogConfig, TermLogger, TerminalMode, WriteLogger};
use std::fs::File;
use std::path::PathBuf;

mod cli;
mod crypto;
mod network;
mod storage;
mod utils;

use cli::commands;
use storage::config::Config;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line arguments
    let matches = App::new("secnet")
        .version("0.1.0")
        .author("Privacy Network Protocol")
        .about("Privacy-focused secure messaging CLI")
        .arg(
            Arg::with_name("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Sets a custom config file")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("verbose")
                .short('v')
                .long("verbose")
                .help("Enable verbose output"),
        )
        .arg(
            Arg::with_name("log-level")
                .long("log-level")
                .value_name("LEVEL")
                .help("Set logging level: error, warn, info, debug, trace")
                .default_value("info")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("log-file")
                .long("log-file")
                .value_name("FILE")
                .help("Log to file instead of terminal")
                .takes_value(true),
        )
        .subcommand(
            SubCommand::with_name("keygen")
                .about("Generate new identity keys")
                .arg(
                    Arg::with_name("server")
                        .long("server")
                        .value_name("URL")
                        .help("Server URL [default: https://localhost:8080]")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("alias")
                        .long("alias")
                        .value_name("ALIAS")
                        .help("Local alias for these keys (never shared)")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("export-pub")
                        .long("export-pub")
                        .value_name("FILE")
                        .help("Export public key to file for sharing")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("rotate")
                        .long("rotate")
                        .help("Rotate existing keys"),
                )
                .arg(
                    Arg::with_name("backup")
                        .long("backup")
                        .value_name("FILE")
                        .help("Create encrypted backup of keys")
                        .takes_value(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("connect")
                .about("Connect anonymously to server")
                .arg(
                    Arg::with_name("server")
                        .long("server")
                        .value_name("URL")
                        .help("Server URL")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("background")
                        .long("background")
                        .help("Run in background mode"),
                )
                .arg(
                    Arg::with_name("timeout")
                        .long("timeout")
                        .value_name("SECS")
                        .help("Connection timeout in seconds")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("refresh-token")
                        .long("refresh-token")
                        .help("Get new connection token"),
                ),
        )
        .subcommand(
            SubCommand::with_name("peer")
                .about("Manage peer connections")
                .subcommand(SubCommand::with_name("list").about("List known peers (stored locally)"))
                .subcommand(
                    SubCommand::with_name("add")
                        .about("Add peer using their public key")
                        .arg(
                            Arg::with_name("key-file")
                                .long("key-file")
                                .value_name("FILE")
                                .help("Import peer's public key from file")
                                .takes_value(true),
                        )
                        .arg(
                            Arg::with_name("alias")
                                .long("alias")
                                .value_name("ALIAS")
                                .help("Assign local alias to peer (never shared)")
                                .takes_value(true),
                        ),
                )
                .subcommand(
                    SubCommand::with_name("verify")
                        .about("Verify peer's key fingerprint")
                        .arg(Arg::with_name("FINGERPRINT").required(true)),
                )
                .subcommand(
                    SubCommand::with_name("remove")
                        .about("Remove peer from trusted list")
                        .arg(Arg::with_name("FINGERPRINT").required(true)),
                )
                .subcommand(
                    SubCommand::with_name("init-session")
                        .about("Initialize secure session with peer")
                        .arg(Arg::with_name("FINGERPRINT").required(true)),
                ),
        )
        .subcommand(
            SubCommand::with_name("msg")
                .about("Send and receive encrypted messages")
                .subcommand(
                    SubCommand::with_name("send")
                        .about("Send message to peer")
                        .arg(Arg::with_name("FINGERPRINT").required(true))
                        .arg(Arg::with_name("MESSAGE").required(true))
                        .arg(
                            Arg::with_name("topic")
                                .long("topic")
                                .value_name("TOPIC_HASH")
                                .help("Send to topic instead of peer")
                                .takes_value(true),
                        )
                        .arg(
                            Arg::with_name("file")
                                .long("file")
                                .value_name("FILE")
                                .help("Send file instead of text message")
                                .takes_value(true),
                        ),
                )
                .subcommand(SubCommand::with_name("fetch").about("Fetch pending messages"))
                .subcommand(
                    SubCommand::with_name("read")
                        .about("Read specific message or all unread")
                        .arg(Arg::with_name("ID")),
                )
                .subcommand(
                    SubCommand::with_name("chat")
                        .about("Enter interactive chat mode with peer")
                        .arg(Arg::with_name("FINGERPRINT").required(true)),
                ),
        )
        .subcommand(
            SubCommand::with_name("topic")
                .about("Manage anonymous topics")
                .subcommand(SubCommand::with_name("create").about("Create new topic (returns hash)"))
                .subcommand(SubCommand::with_name("list").about("List subscribed topics"))
                .subcommand(
                    SubCommand::with_name("subscribe")
                        .about("Subscribe to topic")
                        .arg(Arg::with_name("TOPIC_HASH").required(true)),
                )
                .subcommand(
                    SubCommand::with_name("unsubscribe")
                        .about("Unsubscribe from topic")
                        .arg(Arg::with_name("TOPIC_HASH").required(true)),
                )
                .subcommand(
                    SubCommand::with_name("publish")
                        .about("Publish to topic")
                        .arg(Arg::with_name("TOPIC_HASH").required(true))
                        .arg(Arg::with_name("MESSAGE").required(true)),
                ),
        )
        .subcommand(
            SubCommand::with_name("status")
                .about("Check status")
                .arg(
                    Arg::with_name("keys")
                        .long("keys")
                        .help("Show key status and fingerprints"),
                )
                .arg(
                    Arg::with_name("connection")
                        .long("connection")
                        .help("Show anonymous connection status"),
                )
                .arg(
                    Arg::with_name("messages")
                        .long("messages")
                        .help("Show message stats (counts only)"),
                )
                .arg(
                    Arg::with_name("entropy")
                        .long("entropy")
                        .help("Check system entropy for key generation"),
                ),
        )
        .get_matches();

    // Set up logging
    let log_level = match matches.value_of("log-level").unwrap_or("info") {
        "error" => LevelFilter::Error,
        "warn" => LevelFilter::Warn,
        "info" => LevelFilter::Info,
        "debug" => LevelFilter::Debug,
        "trace" => LevelFilter::Trace,
        _ => LevelFilter::Info,
    };

    // Use more verbose logging if --verbose is specified
    let log_level = if matches.is_present("verbose") {
        LevelFilter::Debug
    } else {
        log_level
    };

    // Log to file or terminal
    if let Some(log_file) = matches.value_of("log-file") {
        WriteLogger::init(
            log_level,
            SimplelogConfig::default(),
            File::create(log_file).expect("Failed to create log file"),
        )
        .expect("Failed to initialize file logger");
        info!("Logging to file: {}", log_file);
    } else {
        TermLogger::init(
            log_level,
            SimplelogConfig::default(),
            TerminalMode::Mixed,
            ColorChoice::Auto,
        )
        .expect("Failed to initialize terminal logger");
    }

    // Log startup information
    info!("Starting secnet v0.1.0");
    debug!("Log level set to: {:?}", log_level);

    // Load configuration
    let config_path = matches
        .value_of("config")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let mut path = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
            path.push("secnet");
            path.push("config.json");
            path
        });

    debug!("Using config file: {:?}", config_path);
    let config = match Config::load(&config_path) {
        Ok(config) => {
            info!("Configuration loaded successfully");
            config
        }
        Err(e) => {
            warn!("Failed to load config, using defaults: {:?}", e);
            let default_config = Config::default();
            if let Err(e) = default_config.save(&config_path) {
                warn!("Failed to save default config: {:?}", e);
            } else {
                info!("Default configuration saved to {:?}", config_path);
            }
            default_config
        }
    };

    // Process subcommands
    match matches.subcommand() {
        Some(("keygen", sub_m)) => {
            info!("Executing key generation command");
            commands::keygen::execute(sub_m, &config).await?
        }
        Some(("connect", sub_m)) => {
            info!("Executing connect command");
            commands::connect::execute(sub_m, &config).await?
        }
        Some(("peer", sub_m)) => {
            info!("Executing peer management command");
            commands::peer::execute(sub_m, &config).await?
        }
        Some(("msg", sub_m)) => {
            info!("Executing message command");
            commands::msg::execute(sub_m, &config).await?
        }
        Some(("topic", sub_m)) => {
            info!("Executing topic command");
            commands::topic::execute(sub_m, &config).await?
        }
        Some(("status", sub_m)) => {
            info!("Executing status command");
            commands::status::execute(sub_m, &config).await?
        }
        _ => {
            println!("No command specified. Use --help for usage information.");
            info!("No command specified, exiting");
        }
    }

    info!("secnet terminating normally");
    Ok(())
}