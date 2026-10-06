//! `lfcp-admin`: administer an OpenLFCP reference server (POST-014). See
//! [`USAGE`] and the server README "Administration".

use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use lfcp::base::PrincipalId;
use lfcp_admin::client::{Admin, Hosting, QuotaOverride};
use lfcp_admin::http::{Url, DEFAULT_URL};
use lfcp_admin::key::{self, KEY_ENV};
use lfcp_admin::Error;
use serde_json::Value;
use zeroize::Zeroizing;

const USAGE: &str = "usage: lfcp-admin [--url URL] [--key FILE] COMMAND

  keygen                       create the admin key FILE (mode 0600); prints its Principal ID
  pair --setup-code CODE|-     pair the key as the server's administrator ('-': read the code
                               from stdin, e.g. ssh HOST sudo cat .../setup-code | lfcp-admin pair --setup-code -)
  pair --setup-code-file PATH  the same, the code read from a file
  status                       server ID, version, limits, administrators, hosted Resources
  hosting get                  the hosting policy
  hosting set quota|open       anyone may host, with or without quotas
  hosting set allow_list [--principal ID]... [--credentials-file PATH]
                               only these Principals, or holders of these hosting
                               credentials (PATH: one hex credential per line)
  quota list                   the default quota and every override
  quota get ID                 a Principal's override, quota and usage
  quota set ID [--resources N] [--bytes B] [--resource-bytes B]
                               set its override (an omitted field keeps the default)
  quota clear ID               remove its override

  --url   the server, plain http (default http://127.0.0.1:17820, the server's
          loopback port over an SSH tunnel: ssh -N -L 17820:127.0.0.1:17820 HOST)
  --key   the admin key file (default: $LFCP_ADMIN_KEY)

ID is a 64-hex Principal ID. Secrets (key, setup code, credentials, tokens)
are never printed. Exit status: 0 done, 1 refused or failed, 2 usage.";

fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("lfcp-admin: {error}");
            if matches!(error, Error::Usage(_)) {
                eprintln!("\n{USAGE}");
            }
            ExitCode::from(error.exit_code())
        }
    }
}

fn usage(message: impl Into<String>) -> Error {
    Error::Usage(message.into())
}

/// Take `--flag VALUE` out of `args`; every occurrence when `many`.
fn take_values(args: &mut Vec<String>, flag: &str) -> Result<Vec<String>, Error> {
    let mut values = Vec::new();
    while let Some(i) = args.iter().position(|a| a == flag) {
        if i + 1 >= args.len() {
            return Err(usage(format!("{flag} needs a value")));
        }
        values.push(args.remove(i + 1));
        args.remove(i);
    }
    Ok(values)
}

fn take_value(args: &mut Vec<String>, flag: &str) -> Result<Option<String>, Error> {
    let mut values = take_values(args, flag)?;
    if values.len() > 1 {
        return Err(usage(format!("{flag} given twice")));
    }
    Ok(values.pop())
}

fn principal(text: &str) -> Result<PrincipalId, Error> {
    PrincipalId::from_hex(text).map_err(|_| usage(format!("{text:?} is not a 64-hex Principal ID")))
}

fn number(flag: &str, value: Option<String>) -> Result<Option<u64>, Error> {
    value
        .map(|v| {
            v.parse::<u64>()
                .map_err(|_| usage(format!("{flag} {v:?} is not a whole number")))
        })
        .transpose()
}

fn print(value: &Value) -> Result<(), Error> {
    let text = serde_json::to_string_pretty(value).expect("JSON prints");
    writeln!(std::io::stdout(), "{text}").map_err(|e| Error::Io(e.to_string()))
}

/// The one-time setup code: from `--setup-code` (`-` reads stdin) or
/// `--setup-code-file`.
fn setup_code(args: &mut Vec<String>) -> Result<Zeroizing<String>, Error> {
    let inline = take_value(args, "--setup-code")?;
    let file = take_value(args, "--setup-code-file")?;
    let text = match (inline, file) {
        (Some(code), None) if code == "-" => {
            let mut line = String::new();
            std::io::stdin()
                .lock()
                .read_line(&mut line)
                .map_err(|e| Error::Io(format!("cannot read the setup code from stdin: {e}")))?;
            line
        }
        (Some(code), None) => code,
        (None, Some(path)) => std::fs::read_to_string(&path)
            .map_err(|e| Error::Io(format!("cannot read {path}: {e}")))?,
        (None, None) => {
            return Err(usage(
                "pair needs --setup-code CODE|- or --setup-code-file PATH",
            ))
        }
        (Some(_), Some(_)) => {
            return Err(usage("give --setup-code or --setup-code-file, not both"))
        }
    };
    let code = Zeroizing::new(text.trim().to_owned());
    if code.is_empty() {
        return Err(usage("the setup code is empty"));
    }
    Ok(code)
}

fn credentials(path: &str) -> Result<Vec<Zeroizing<Vec<u8>>>, Error> {
    let text = Zeroizing::new(
        std::fs::read_to_string(path).map_err(|e| Error::Io(format!("cannot read {path}: {e}")))?,
    );
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .enumerate()
        .map(|(i, line)| {
            lfcp::base::from_hex(line)
                .map(Zeroizing::new)
                .map_err(|_| usage(format!("{path}: credential {} is not hex", i + 1)))
        })
        .collect()
}

fn run(mut args: Vec<String>) -> Result<(), Error> {
    if args.iter().any(|a| a == "-h" || a == "--help") || args.is_empty() {
        println!("{USAGE}");
        return Ok(());
    }
    let url = Url::parse(
        take_value(&mut args, "--url")?
            .as_deref()
            .unwrap_or(DEFAULT_URL),
    )?;
    let key_path: PathBuf = match take_value(&mut args, "--key")? {
        Some(path) => path.into(),
        None => std::env::var_os(KEY_ENV)
            .map(PathBuf::from)
            .ok_or_else(|| usage(format!("no admin key: pass --key FILE or set {KEY_ENV}")))?,
    };
    let command = args.remove(0);
    if command == "keygen" {
        no_more(&args)?;
        let id = key::generate(&key_path)?;
        println!("admin key written to {}", key_path.display());
        println!("principal: {}", id.to_hex());
        return Ok(());
    }
    let admin = Admin::new(url, key::load(&key_path)?);
    match command.as_str() {
        "pair" => {
            let code = setup_code(&mut args)?;
            no_more(&args)?;
            let answer = admin.pair(&code)?;
            println!(
                "paired: {} is the server's administrator",
                answer["admin"].as_str().unwrap_or("?")
            );
            Ok(())
        }
        "status" => {
            no_more(&args)?;
            print(&admin.status()?)
        }
        "hosting" => match sub(&mut args)?.as_str() {
            "get" => {
                no_more(&args)?;
                print(&admin.hosting()?)
            }
            "set" => {
                let mode = sub(&mut args)?;
                let hosting = match mode.as_str() {
                    "quota" => Hosting::Quota,
                    "open" => Hosting::Open,
                    "allow_list" => {
                        let principals = take_values(&mut args, "--principal")?
                            .iter()
                            .map(|p| principal(p))
                            .collect::<Result<_, _>>()?;
                        let credentials = match take_value(&mut args, "--credentials-file")? {
                            Some(path) => credentials(&path)?,
                            None => Vec::new(),
                        };
                        Hosting::AllowList {
                            principals,
                            credentials,
                        }
                    }
                    other => {
                        return Err(usage(format!(
                            "hosting set {other:?}: use quota, open or allow_list"
                        )))
                    }
                };
                no_more(&args)?;
                print(&admin.set_hosting(&hosting)?)
            }
            other => Err(usage(format!("hosting {other:?}: use get or set"))),
        },
        "quota" => match sub(&mut args)?.as_str() {
            "list" => {
                no_more(&args)?;
                print(&admin.quotas()?)
            }
            "get" => {
                let id = principal(&sub(&mut args)?)?;
                no_more(&args)?;
                print(&admin.quota(&id)?)
            }
            "set" => {
                let id = principal(&sub(&mut args)?)?;
                let quota = QuotaOverride {
                    resources: number("--resources", take_value(&mut args, "--resources")?)?,
                    bytes: number("--bytes", take_value(&mut args, "--bytes")?)?,
                    resource_bytes: number(
                        "--resource-bytes",
                        take_value(&mut args, "--resource-bytes")?,
                    )?,
                };
                no_more(&args)?;
                if quota == QuotaOverride::default() {
                    return Err(usage(
                        "quota set needs --resources, --bytes or --resource-bytes (quota clear removes an override)",
                    ));
                }
                print(&admin.set_quota(&id, quota)?)
            }
            "clear" => {
                let id = principal(&sub(&mut args)?)?;
                no_more(&args)?;
                print(&admin.clear_quota(&id)?)
            }
            other => Err(usage(format!(
                "quota {other:?}: use list, get, set or clear"
            ))),
        },
        other => Err(usage(format!("unknown command {other:?}"))),
    }
}

/// The next positional argument.
fn sub(args: &mut Vec<String>) -> Result<String, Error> {
    if args.is_empty() || args[0].starts_with("--") {
        return Err(usage("a subcommand or argument is missing"));
    }
    Ok(args.remove(0))
}

fn no_more(args: &[String]) -> Result<(), Error> {
    match args.first() {
        Some(extra) => Err(usage(format!("unexpected argument {extra:?}"))),
        None => Ok(()),
    }
}
