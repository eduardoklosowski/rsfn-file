use std::{fs::File, io, path::PathBuf};

use clap::{ArgMatches, Command, arg, command, value_parser};
use clap_complete::{Shell, generate};

fn build_cli() -> Command {
    command!("rsfnfile")
        .subcommand_required(true)
        .subcommand(
            command!("completion")
                .about("Gera completion para o shell")
                .arg(
                    arg!(<shell> "Shell que o completion deve ser gerado")
                        .value_parser(value_parser!(Shell))
                )
                .arg(
                    arg!(-o --output <PATH> "Arquivo de saída, se não informado o STDOUT será escrito")
                        .value_parser(value_parser!(PathBuf))
                )
        )
}

fn main() {
    let result = match build_cli().get_matches().subcommand() {
        Some(("completion", matches)) => generate_completion(matches),
        _ => unreachable!(),
    };

    if let Err(error) = result {
        eprintln!("ERRO: {error}");
        std::process::exit(1);
    }
}

fn open_input(filepath: Option<&PathBuf>) -> Result<Box<dyn io::Read>, String> {
    match filepath {
        None => Ok(Box::new(io::BufReader::new(io::stdin()))),
        Some(filepath) => Ok(Box::new(io::BufReader::new(
            File::open(filepath).map_err(|error| format!("Falha ao abrir arquivo: {error}"))?,
        ))),
    }
}

fn open_output(filepath: Option<&PathBuf>) -> Result<Box<dyn io::Write>, String> {
    match filepath {
        None => Ok(Box::new(io::stdout())),
        Some(filepath) => {
            Ok(Box::new(File::create(filepath).map_err(|error| {
                format!("Falha ao abrir arquivo: {error}")
            })?))
        }
    }
}

fn generate_completion(matches: &ArgMatches) -> Result<(), String> {
    let mut output = open_output(matches.get_one("output"))
        .map_err(|error| format!("Falha na saída\n{error}"))?;

    let mut cli = build_cli();
    let name = cli.get_name().to_string();
    match matches.get_one::<Shell>("shell").copied() {
        Some(shell) => generate(shell, &mut cli, name, &mut output),
        None => unreachable!(),
    }
    Ok(())
}
