use std::{fs::File, io, path::PathBuf};

use clap::{ArgAction, Command, arg, command, value_parser};
use clap_complete::{Shell, generate};
use rsfn_file::header::Header;

fn build_cli() -> Command {
    command!("rsfnfile")
        .subcommand_required(true)
        .subcommand(
            command!("header")
                .about("Mostra o cabeçalho de segurança do arquivo da RSFN")
                .arg(
                    arg!(-i --in <PATH> "Arquivo de entrada, se não informado o STDIN será lido")
                        .value_parser(value_parser!(PathBuf))
                )
                .arg(
                    arg!(-o --out <PATH> "Arquivo de saída, se não informado o STDOUT será escrito")
                        .value_parser(value_parser!(PathBuf))
                )
                .arg(
                    arg!(verbose: -q --quiet "Não imprime o cabeçalho de segurança do arquivo")
                        .action(ArgAction::SetFalse)
                )
                .arg(
                    arg!(verifyheader: -n --noverifyheader "Não verifica se o cabelhaço de segurança tem valores válidos nos campos")
                        .action(ArgAction::SetFalse)
                )
        )
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
            Ok(file) => file,
            Err(error) => {
                eprintln!("ERRO: Falha ao abrir arquivo de entrada: {error}");
                std::process::exit(1);
            }
        })),
    }
}

fn open_output(filepath: Option<&PathBuf>) -> Box<dyn io::Write> {
    match filepath {
        None => Box::new(io::stdout()),
        Some(filepath) => Box::new(match File::create(filepath) {
            Ok(file) => file,
            Err(error) => {
                eprintln!("ERRO: Falha ao abrir arquivo de saída: {error}");
                std::process::exit(1);
            }
        }),
    }
}

fn main() -> io::Result<()> {
    match build_cli().get_matches().subcommand() {
        Some(("header", matches)) => {
            let mut input = open_input(matches.get_one("in"));
            let mut output = open_output(matches.get_one("out"));

            let header = match Header::read_from_file(&mut input) {
                Ok(header) => header,
                Err(error) => {
                    eprintln!("ERRO: Falha ao ler cabeçalho de segurança: {error}");
                    std::process::exit(1);
                }
            };

            if matches.get_flag("verbose") {
                writeln!(output, "{header}")?;
            }
            if matches.get_flag("verifyheader")
                && let Err(error) = header.is_header_valid()
            {
                eprintln!("ERRO: Cabeçalho de segurança inválido: {error}");
                std::process::exit(1);
            }
        }

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
