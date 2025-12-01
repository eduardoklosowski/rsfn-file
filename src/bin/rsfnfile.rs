use std::{
    fs::File,
    io::{self, Write},
    path::PathBuf,
};

use clap::{ArgAction, ArgMatches, Command, arg, command, value_parser};
use clap_complete::{Shell, generate};
use rsfn_file::{compress::Compressors, encode::Encoders, header};

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
            command!("enc")
                .about("Criptografa arquivo")
                .arg(
                    arg!(<src_cert> "Certificado da origem do arquivo")
                        .value_parser(value_parser!(PathBuf))
                )
                .arg(
                    arg!(<src_key> "Chave privada da origem do arquivo")
                        .value_parser(value_parser!(PathBuf))
                )
                .arg(
                    arg!(<dst_cert> "Certificado do destino do arquivo")
                        .value_parser(value_parser!(PathBuf))
                )
                .arg(
                    arg!([input] "Arquivo de entrada, se não informado o STDIN será lido")
                        .value_parser(value_parser!(PathBuf))
                )
                .arg(
                    arg!(-o --output <PATH> "Arquivo de saída, se não informado o STDOUT será escrito")
                        .value_parser(value_parser!(PathBuf))
                )
                .arg(
                    arg!(specialtreatment: --specialtreatment <VALUE> "Valor para o campo de tratamento especial (C04)")
                        .value_parser(value_parser!(header::SpecialTreatment))
                )
                .arg(
                    arg!(crypt: -p --plain "Não criptografa os dados")
                        .action(ArgAction::SetFalse)
                )
                .arg(
                    arg!(-g --gzip "Compacta arquivo com gzip (RFC 1952)")
                        .action(ArgAction::SetTrue)
                )
                .arg(
                    arg!(encode: -r --raw "Não realiza a conversão dos dados de UTF-8 para UTF-16BE")
                        .action(ArgAction::SetFalse)
                )
                .arg(
                    arg!(verifycert: -c --noverifycert "Não verifica se os certificados são os mesmos do cabeçalho de segurança")
                        .action(ArgAction::SetFalse)
                )
        )
        .subcommand(
            command!("dec")
                .about("Descriptografa arquivo")
                .arg(
                    arg!(<src_cert> "Certificado da origem do arquivo")
                        .value_parser(value_parser!(PathBuf))
                )
                .arg(
                    arg!(<dst_cert> "Certificado do destino do arquivo")
                        .value_parser(value_parser!(PathBuf))
                )
                .arg(
                    arg!(<dst_key> "Chave privada do destino do arquivo")
                        .value_parser(value_parser!(PathBuf))
                )
                .arg(
                    arg!([input] "Arquivo de entrada, se não informado o STDIN será lido")
                        .value_parser(value_parser!(PathBuf))
                )
                .arg(
                    arg!(-o --output <PATH> "Arquivo de saída, se não informado o STDOUT será escrito")
                        .value_parser(value_parser!(PathBuf))
                )
                .arg(
                    arg!(decompress: -d --nodecompress "Não descompacta dados se eles estiverem compactados")
                        .action(ArgAction::SetFalse)
                )
                .arg(
                    arg!(decode: -r --raw "Não realiza a conversão dos dados de UTF-16BE para UTF-8")
                        .action(ArgAction::SetFalse)
                )
                .arg(
                    arg!(verifyheader: -n --noverifyheader "Não verifica se o cabelhaço de segurança tem valores válidos nos campos")
                        .action(ArgAction::SetFalse)
                )
                .arg(
                    arg!(verifycert: -c --noverifycert "Não verifica se os certificados são os mesmos do cabeçalho de segurança")
                        .action(ArgAction::SetFalse)
                )
                .arg(
                    arg!(verifysign: -s --noverifysign "Não verifica assinatura do arquivo")
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
        Some(("enc", matches)) => encrypt_file(matches),
        Some(("dec", matches)) => decrypt_file(matches),
        Some(("completion", matches)) => generate_completion(matches),
        _ => unreachable!(),
    };

    if let Err(error) = result {
        eprintln!("ERRO: {error}");
        std::process::exit(1);
    }
}

fn load_file(filepath: &PathBuf) -> Result<Vec<u8>, String> {
    std::fs::read(filepath).map_err(|error| {
        let filepath = filepath.to_str().unwrap_or("[caracteres inválidos]");
        format!("Falha na leitura do arquivo {filepath}: {error}")
    })
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

    let header = rsfn_file::actions::load_header(&mut input)?;
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

fn encrypt_file(matches: &ArgMatches) -> Result<(), String> {
    let mut input = open_input(matches.get_one("input"))
        .map_err(|error| format!("Falha na entrada\n{error}"))?;
    let mut output = open_output(matches.get_one("output"))
        .map_err(|error| format!("Falha na saída\n{error}"))?;

    let src_cert = load_file(
        matches
            .get_one("src_cert")
            .expect("Argumento do certificado da origem faltando"),
    )?;
    let src_key = load_file(
        matches
            .get_one("src_key")
            .expect("Argumento da chave privada da origem faltando"),
    )?;

    let dst_cert = load_file(
        matches
            .get_one("dst_cert")
            .expect("Argumento do certificado do destino faltando"),
    )?;

    let params = rsfn_file::actions::EncryptParams {
        verify_certs: matches.get_flag("verifycert"),
        special_treatment: matches
            .get_one::<header::SpecialTreatment>("specialtreatment")
            .cloned(),
        crypt: matches.get_flag("crypt"),
        encoder: match matches.get_flag("encode") {
            true => Encoders::default(),
            false => Encoders::Plain,
        },
        compressor: match matches.get_flag("gzip") {
            true => Compressors::Gzip,
            false => Compressors::Plain,
        },
    };
    let data = rsfn_file::actions::encrypt(&src_cert, &src_key, &dst_cert, &params, &mut input)?;

    output
        .write_all(&data)
        .map_err(|error| format!("Falha ao escrever os dados criptografados\n{error}"))?;

    Ok(())
}

fn decrypt_file(matches: &ArgMatches) -> Result<(), String> {
    let mut input = open_input(matches.get_one("input"))
        .map_err(|error| format!("Falha na entrada\n{error}"))?;
    let mut output = open_output(matches.get_one("output"))
        .map_err(|error| format!("Falha na saída\n{error}"))?;

    let src_cert = load_file(
        matches
            .get_one("src_cert")
            .expect("Argumento do certificado da origem faltando"),
    )?;

    let dst_cert = load_file(
        matches
            .get_one("dst_cert")
            .expect("Argumento do certificado do destino faltando"),
    )?;
    let dst_key = load_file(
        matches
            .get_one("dst_key")
            .expect("Argumento da chave privada do destino faltando"),
    )?;

    let params = rsfn_file::actions::DecryptParams {
        decompress: matches.get_flag("decompress"),
        decode: matches.get_flag("decode"),
        verify_header: matches.get_flag("verifyheader"),
        verify_certs: matches.get_flag("verifycert"),
        verify_sign: matches.get_flag("verifysign"),
    };
    let data = rsfn_file::actions::decrypt(&src_cert, &dst_cert, &dst_key, &params, &mut input)?;

    output
        .write_all(&data)
        .map_err(|error| format!("Falha ao escrever os dados descriptografados\n{error}"))?;

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
