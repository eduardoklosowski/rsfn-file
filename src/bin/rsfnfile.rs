use std::{fs::File, io, path::PathBuf};

use clap::{Command, arg, command, value_parser};
use clap_complete::{Shell, generate};

fn build_cli() -> Command {
    command!("rsfnfile")
        .subcommand_required(true)
        .subcommand(
            command!("completion")
                .about("Gera completion para o shell")
                .arg(
                    arg!(-o --out <PATH> "Arquivo de saída, se não informado o STDOUT será escrito")
                        .value_parser(value_parser!(PathBuf))
                )
                .arg(
                    arg!(<shell> "Shell que o completion deve ser gerado")
                        .value_parser(value_parser!(Shell))
                )
        )
}

fn open_input(filepath: Option<&PathBuf>) -> Box<dyn io::Read> {
    match filepath {
        None => Box::new(io::BufReader::new(io::stdin())),
        Some(filepath) => Box::new(io::BufReader::new(match File::open(filepath) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("ERRO: Falha ao abrir arquivo de entrada: {e}");
                std::process::exit(2);
            }
        })),
    }
}

fn open_output(filepath: Option<&PathBuf>) -> Box<dyn io::Write> {
    match filepath {
        None => Box::new(io::stdout()),
        Some(filepath) => Box::new(match File::create(filepath) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("ERRO: Falha ao abrir arquivo de saída: {e}");
                std::process::exit(2);
            }
        }),
    }
}

fn main() -> io::Result<()> {
    match build_cli().get_matches().subcommand() {
        Some(("completion", matches)) => {
            let mut output = open_output(matches.get_one("out"));

            let mut cli = build_cli();
            let name = cli.get_name().to_string();
            match matches.get_one::<Shell>("shell").copied() {
                Some(shell) => generate(shell, &mut cli, name, &mut output),
                None => unreachable!(),
            }
        }

        _ => unreachable!(),
    }

    Ok(())
}
