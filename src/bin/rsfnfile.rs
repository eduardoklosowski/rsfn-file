use std::{fs::File, io, path::PathBuf};

use clap::{ArgAction, Command, arg, command, value_parser};
use clap_complete::{Shell, generate};
use rsfn_file::{
    cert::Certificate,
    ciphers::{Aes256, RsaPrivate},
    header::{self, Header},
};

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
            command!("enc")
                .about("Criptografa arquivo")
                .arg(
                    arg!(-i --in <PATH> "Arquivo de entrada, se não informado o STDIN será lido")
                        .value_parser(value_parser!(PathBuf))
                )
                .arg(
                    arg!(-o --out <PATH> "Arquivo de saída, se não informado o STDOUT será escrito")
                        .value_parser(value_parser!(PathBuf))
                )
                .arg(
                    arg!(<src_cert> "Certificado da origem do arquivo")
                        .value_parser(value_parser!(PathBuf))
                )
                .arg(
                    arg!(<src_key> "Chave RSA privada da origem do arquivo")
                        .value_parser(value_parser!(PathBuf))
                )
                .arg(
                    arg!(<dst_cert> "Certificado do destino do arquivo")
                        .value_parser(value_parser!(PathBuf))
                )
        )
        .subcommand(
            command!("dec")
                .about("Descriptografa arquivo")
                .arg(
                    arg!(-i --in <PATH> "Arquivo de entrada, se não informado o STDIN será lido")
                        .value_parser(value_parser!(PathBuf))
                )
                .arg(
                    arg!(-o --out <PATH> "Arquivo de saída, se não informado o STDOUT será escrito")
                        .value_parser(value_parser!(PathBuf))
                )
                .arg(
                    arg!(<src_cert> "Certificado da origem do arquivo")
                        .value_parser(value_parser!(PathBuf))
                )
                .arg(
                    arg!(<dst_cert> "Certificado do destino do arquivo")
                        .value_parser(value_parser!(PathBuf))
                )
                .arg(
                    arg!(<dst_key> "Chave RSA privada do destino do arquivo")
                        .value_parser(value_parser!(PathBuf))
                )
                .arg(
                    arg!(verifysign: -n --noverifysign "Não verifica assinatura do arquivo")
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
        Some(("header", matches)) => {
            let mut input = open_input(matches.get_one("in"));
            let mut output = open_output(matches.get_one("out"));

            let header = match Header::read_from_file(&mut input) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("ERRO: Falha ao ler cabeçalho: {e}");
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

        Some(("enc", matches)) => {
            let mut input = open_input(matches.get_one("in"));
            let mut output = open_output(matches.get_one("out"));

            let src_cert = matches
                .get_one::<PathBuf>("src_cert")
                .expect("Argumento do certificado da origem faltando");
            let src_cert =
                std::fs::read(src_cert).expect("Erro ao ler arquivo do certificado da origem");
            let src_cert = Certificate::load(&src_cert).expect("Erro ao ler certificado da origem");
            let src_key = matches
                .get_one::<PathBuf>("src_key")
                .expect("Argumento da chave RSA privada da origem faltando");
            let src_key = std::fs::read_to_string(src_key)
                .expect("Erro ao ler arquivo da chave RSA privada da origem");
            let src_key =
                RsaPrivate::load_pem(&src_key).expect("Erro ao ler chave RSA privada da origem");
            let dst_cert = matches
                .get_one::<PathBuf>("dst_cert")
                .expect("Argumento do certificado do destino faltando");
            let dst_cert =
                std::fs::read(dst_cert).expect("Erro ao ler arquivo do certificado do destino");
            let dst_cert =
                Certificate::load(&dst_cert).expect("Erro ao ler certificado do destino");
            let dst_key = dst_cert
                .rsa_pub_key()
                .expect("Erro ao ler chave RSA pública do certificado do destino");

            let mut data = Vec::new();
            input
                .read_to_end(&mut data)
                .expect("Erro ao ler dados para criptografar");

            let aes = Aes256::generate_new_key();
            let ciphertext = aes.encrypt(&data).expect("Erro ao criptografar dados");
            let sym_key = dst_key
                .encrypt(&aes.export_key())
                .expect("Erro ao criptografar chave simétrica");
            let sign = src_key.sign(&data);

            let header = Header {
                len: header::HeaderLen::Default,
                version: header::ProtocolVersion::Version3,
                error: header::ErrorCode::NoError,
                special_treatment: header::SpecialTreatment::Normal,
                reserved: header::Reserved::NoValue,
                dst_key_algo: header::AsymmetricKeyAlgo::RSA2048,
                sym_key_algo: header::SymmetricKeyAlgo::Aes,
                src_key_algo: header::AsymmetricKeyAlgo::RSA2048,
                hash_algo: header::HashAlgo::SHA256,
                dst_pc_cert: header::PcCert::SpbSerpro,
                dst_cert_serial: dst_cert.serial().into(),
                src_pc_cert: header::PcCert::SpbSerpro,
                src_cert_serial: src_cert.serial().into(),
                buffer_sym_key: sym_key
                    .try_into()
                    .expect("Tamanho da chave simétrica incorreto"),
                buffer_hash: sign.try_into().expect("Tamanho da assinatura incorreto"),
            };
            header
                .write(&mut output)
                .expect("Erro ao escrever cabeçalho de segurança");
            output
                .write_all(&ciphertext)
                .expect("Erro ao escrever dados criptografados");
        }

        Some(("dec", matches)) => {
            let mut input = open_input(matches.get_one("in"));
            let mut output = open_output(matches.get_one("out"));

            let src_cert = matches
                .get_one::<PathBuf>("src_cert")
                .expect("Argumento do certificado da origem faltando");
            let src_cert =
                std::fs::read(src_cert).expect("Erro ao ler arquivo do certificado da origem");
            let src_cert = Certificate::load(&src_cert).expect("Erro ao ler certificado da origem");
            let src_key = src_cert
                .rsa_pub_key()
                .expect("Erro ao ler chave RSA pública do certificado da origem");
            let dst_cert = matches
                .get_one::<PathBuf>("dst_cert")
                .expect("Argumento do certificado do destino faltando");
            let dst_cert =
                std::fs::read(dst_cert).expect("Erro ao ler arquivo do certificado do destino");
            let dst_cert =
                Certificate::load(&dst_cert).expect("Erro ao ler certificado do destino");
            let dst_key = matches
                .get_one::<PathBuf>("dst_key")
                .expect("Argumento da chave RSA privada do destino faltando");
            let dst_key = std::fs::read_to_string(dst_key)
                .expect("Erro ao ler arquivo da chave RSA privada do destino");
            let dst_key =
                RsaPrivate::load_pem(&dst_key).expect("Erro ao ler chave RSA privada do destino");

            let header = Header::read_from_file(&mut input)
                .expect("Erro ao ler cabeçalho de segurança do arquivo");
            if header.src_cert_serial.value() != src_cert.serial() {
                eprintln!("ERRO: Certificado de origem não coincide");
                std::process::exit(2);
            }
            if header.dst_cert_serial.value() != dst_cert.serial() {
                eprintln!("ERRO: Certificado de destino não coincide");
                std::process::exit(2);
            }
            let mut data = Vec::new();
            input
                .read_to_end(&mut data)
                .expect("Erro ao ler dados para descriptografar");

            let sym_key = dst_key
                .decrypt(&header.buffer_sym_key.value())
                .expect("Erro ao descriptogradar chave dos dados");
            let aes = Aes256::new(&sym_key);
            let text = aes.decrypt(&data).expect("Erro ao descriptografar dados");

            if matches.get_flag("verifysign")
                && let Err(error) = src_key.verify(&text, &header.buffer_hash.value())
            {
                eprintln!("ERRO: Assinatura inválida: {error}");
                std::process::exit(1);
            }

            output
                .write_all(&text)
                .expect("Erro ao escrever dados criptografados");
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
