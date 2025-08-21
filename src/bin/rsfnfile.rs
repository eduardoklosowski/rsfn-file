use std::{fs::File, io, path::PathBuf};

use clap::{ArgAction, ArgMatches, Command, arg, command, value_parser};
use clap_complete::{Shell, generate};
use rsfn_file::header;

fn build_cli() -> Command {
    command!("rsfnfile")
        .subcommand_required(true)
        .subcommand(
            command!("header")
                .about("Mostra o cabeçalho de segurança do arquivo da RSFN")
                .arg(
                    arg!([input] "Arquivo de entrada, se não informado o STDIN será lido")
                        .value_parser(value_parser!(PathBuf))
                )
                .arg(
                    arg!(-o --output <PATH> "Arquivo de saída, se não informado o STDOUT será escrito")
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
        Some(("header", matches)) => dump_header(matches),
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

fn dump_header(matches: &ArgMatches) -> Result<(), String> {
    let mut input = open_input(matches.get_one("input"))
        .map_err(|error| format!("Falha na entrada\n{error}"))?;
    let mut output = open_output(matches.get_one("output"))
        .map_err(|error| format!("Falha na saída\n{error}"))?;

    let header = header::Header::read_from_file(&mut input)
        .map_err(|error| format!("Falha na leitura do cabelho de segurança\n{error}"))?;
    if matches.get_flag("verbose") {
        writeln!(output, "{header}")
            .map_err(|error| format!("Falha ao mostrar cabeçalho de segurança\n{error}"))?;
    }
    if matches.get_flag("verifyheader") {
        header
            .is_valid()
            .map_err(|error| format!("Cabeçalho de segurança inválido\n{error}"))?;
    }
    Ok(())
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
