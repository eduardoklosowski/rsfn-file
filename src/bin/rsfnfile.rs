use std::{
    fs::File,
    io::{self, Read, Write},
    path::PathBuf,
};

use clap::{ArgAction, Command, arg, command, value_parser};
use clap_complete::{Shell, generate};
use libflate::gzip;
use rsfn_file::{
    cert::Certificate,
    ciphers::{Aes256, RsaPrivate, RsaPublic},
    header::{self, AsymmetricKeyAlgo, Header, SpecialTreatment},
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
                    arg!(-g --gzip "Compacta arquivo com gzip (RFC 1952)")
                        .action(ArgAction::SetTrue)
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
                    arg!(decompress: -d --nodecompress "Não realiza descompactação dos dados se eles estiverem compactados")
                        .action(ArgAction::SetFalse)
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

fn load_cert(path: &PathBuf) -> Result<Certificate, String> {
    match std::fs::read(path) {
        Ok(data) => match Certificate::load(&data) {
            Ok(cert) => Ok(cert),
            Err(error) => Err(format!("Certificado inválido: {error}")),
        },
        Err(error) => Err(format!("Leitura do arquivo: {error}")),
    }
}

fn load_key_from_cert(cert: &Certificate) -> Result<(AsymmetricKeyAlgo, RsaPublic), String> {
    match cert.key_type() {
        Ok(key_type) => match key_type {
            algo @ AsymmetricKeyAlgo::RSA1024 | algo @ AsymmetricKeyAlgo::RSA2048 => {
                cert.rsa_pub_key().map(|key| (algo, key))
            }
            algo => Err(format!("Sem implementação para {}", algo.describe_value())),
        },
        Err(error) => Err(error),
    }
}

fn load_key(path: &PathBuf) -> Result<RsaPrivate, String> {
    match std::fs::read_to_string(path) {
        Ok(data) => match RsaPrivate::load_pem(&data) {
            Ok(key) => Ok(key),
            Err(error) => Err(format!("Chave inválida: {error}")),
        },
        Err(error) => Err(format!("Leitura do arquivo: {error}")),
    }
}

fn encode_gzip(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut encoder = gzip::Encoder::new(Vec::new())
        .map_err(|error| format!("Falha ao iniciar o encode do gzip: {error}"))?;
    encoder
        .write_all(data)
        .map_err(|error| format!("Falha na compresão do gzip: {error}"))?;
    encoder
        .finish()
        .into_result()
        .map_err(|error| format!("Falha na compresão do gzip: {error}"))
}

fn decode_gzip(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut decoder = gzip::Decoder::new(data)
        .map_err(|error| format!("Falha ao iniciar decode do gzip: {error}"))?;
    let mut text = Vec::new();
    decoder
        .read_to_end(&mut text)
        .map_err(|error| format!("Falha na descompressão do gzip: {error}"))?;
    Ok(text)
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

        Some(("enc", matches)) => {
            let mut input = open_input(matches.get_one("in"));
            let mut output = open_output(matches.get_one("out"));

            let src_cert = matches
                .get_one::<PathBuf>("src_cert")
                .expect("Argumento do certificado da origem faltando");
            let src_cert = match load_cert(src_cert) {
                Ok(cert) => cert,
                Err(error) => {
                    eprintln!("ERRO: Falha ao carregar certificado da origem: {error}");
                    std::process::exit(1);
                }
            };
            let (src_key_type, src_cert_key) = match load_key_from_cert(&src_cert) {
                Ok(key) => key,
                Err(error) => {
                    eprintln!("ERRO: Falha ao extrair a chave do certificado da origem: {error}");
                    std::process::exit(1);
                }
            };
            let src_key = matches
                .get_one::<PathBuf>("src_key")
                .expect("Argumento da chave privada da origem faltando");
            let src_key = match load_key(src_key) {
                Ok(key) => key,
                Err(error) => {
                    eprintln!("ERRO: Falha ao carregar chave privada da origem: {error}");
                    std::process::exit(1);
                }
            };
            if !src_key.check_public_key(&src_cert_key) {
                eprintln!("ERRO: Chave privada não coresponde ao certificado da origem");
                std::process::exit(1);
            }
            let dst_cert = matches
                .get_one::<PathBuf>("dst_cert")
                .expect("Argumento do certificado do destino faltando");
            let dst_cert = match load_cert(dst_cert) {
                Ok(cert) => cert,
                Err(error) => {
                    eprintln!("ERRO: Falha ao carregar certificado do destino: {error}");
                    std::process::exit(1);
                }
            };
            let (dst_key_type, dst_cert_key) = match load_key_from_cert(&dst_cert) {
                Ok(key) => key,
                Err(error) => {
                    eprintln!("ERRO: Falha ao extrair a chave do certificado do destino: {error}");
                    std::process::exit(1);
                }
            };

            let mut data = Vec::new();
            if let Err(error) = input.read_to_end(&mut data) {
                eprintln!("ERRO: Falha ao ler dados a serem criptografados: {error}");
                std::process::exit(1);
            };
            let data = match matches.get_flag("gzip") {
                true => match encode_gzip(&data) {
                    Ok(data) => data,
                    Err(error) => {
                        eprintln!("ERRO: {error}");
                        std::process::exit(1);
                    }
                },
                false => data,
            };

            let aes = Aes256::generate_new_key();
            let ciphertext = match aes.encrypt(&data) {
                Ok(chiphertext) => chiphertext,
                Err(error) => {
                    eprintln!("ERRO: Falha ao criptografar os dados: {error}");
                    std::process::exit(1);
                }
            };
            let sym_key = match dst_cert_key.encrypt(&aes.export_key()) {
                Ok(sym_key) => sym_key,
                Err(error) => {
                    eprintln!("ERRO: Falha ao criptografar chave simétrica: {error}");
                    std::process::exit(1);
                }
            };
            let sign = src_key.sign(&data);

            let header = Header {
                len: header::HeaderLen::Default,
                version: header::ProtocolVersion::Version3,
                error: header::ErrorCode::NoError,
                special_treatment: if matches.get_flag("gzip") {
                    header::SpecialTreatment::Compress
                } else {
                    header::SpecialTreatment::NotCompress
                },
                reserved: header::Reserved::NoValue,
                dst_key_algo: dst_key_type,
                sym_key_algo: header::SymmetricKeyAlgo::Aes,
                src_key_algo: src_key_type,
                hash_algo: header::HashAlgo::SHA256,
                dst_pc_cert: dst_cert.issuer(),
                dst_cert_serial: dst_cert.serial(),
                src_pc_cert: src_cert.issuer(),
                src_cert_serial: src_cert.serial(),
                buffer_sym_key: sym_key
                    .try_into()
                    .expect("Tamanho da chave simétrica incorreto"),
                buffer_hash: sign.try_into().expect("Tamanho da assinatura incorreto"),
            };

            if let Err(error) = header.write(&mut output) {
                eprintln!("ERRO: Falha ao escrever cabeçalho de segurança: {error}");
                std::process::exit(1);
            }
            if let Err(error) = output.write_all(&ciphertext) {
                eprintln!("ERRO: Falha ao escrever dados criptografados: {error}");
                std::process::exit(1);
            }
        }

        Some(("dec", matches)) => {
            let mut input = open_input(matches.get_one("in"));
            let mut output = open_output(matches.get_one("out"));

            let src_cert = matches
                .get_one::<PathBuf>("src_cert")
                .expect("Argumento do certificado da origem faltando");
            let src_cert = match load_cert(src_cert) {
                Ok(cert) => cert,
                Err(error) => {
                    eprintln!("ERRO: Falha ao carregar certificado da origem: {error}");
                    std::process::exit(1);
                }
            };
            let (src_key_type, src_cert_key) = match load_key_from_cert(&src_cert) {
                Ok(key) => key,
                Err(error) => {
                    eprintln!("ERRO: Falha ao extrair a chave do certificado da origem: {error}");
                    std::process::exit(1);
                }
            };
            let dst_cert = matches
                .get_one::<PathBuf>("dst_cert")
                .expect("Argumento do certificado do destino faltando");
            let dst_cert = match load_cert(dst_cert) {
                Ok(cert) => cert,
                Err(error) => {
                    eprintln!("ERRO: Falha ao carregar certificado do destino: {error}");
                    std::process::exit(1);
                }
            };
            let (dst_key_type, dst_cert_key) = match load_key_from_cert(&dst_cert) {
                Ok(key) => key,
                Err(error) => {
                    eprintln!("ERRO: Falha ao extrair a chave do certificado do destino: {error}");
                    std::process::exit(1);
                }
            };
            let dst_key = matches
                .get_one::<PathBuf>("dst_key")
                .expect("Argumento da chave privada do destino faltando");
            let dst_key = match load_key(dst_key) {
                Ok(key) => key,
                Err(error) => {
                    eprintln!("ERRO: Falha ao carregar chave privada do destino: {error}");
                    std::process::exit(1);
                }
            };
            if !dst_key.check_public_key(&dst_cert_key) {
                eprintln!("ERRO: Chave privada não coresponde ao certificado do destino");
                std::process::exit(1);
            }

            let header = match Header::read_from_file(&mut input) {
                Ok(header) => header,
                Err(error) => {
                    eprintln!("ERRO: Falha ao ler cabeçalho de segurança: {error}");
                    std::process::exit(1);
                }
            };
            if matches.get_flag("verifycert") {
                if header.src_cert_serial != src_cert.serial() {
                    eprintln!("ERRO: Certificado da origem não coincide");
                    std::process::exit(1);
                }
                if header.src_pc_cert != src_cert.issuer() {
                    eprintln!("ERRO: Emissor do certificado da origem não coincide");
                    std::process::exit(1);
                }
                if header.src_key_algo != src_key_type {
                    eprintln!("ERRO: Tipo da chave do certificado da origem não coincide");
                    std::process::exit(1);
                }

                if header.dst_cert_serial != dst_cert.serial() {
                    eprintln!("ERRO: Certificado do destino não coincide");
                    std::process::exit(1);
                }
                if header.dst_pc_cert != dst_cert.issuer() {
                    eprintln!("ERRO: Emissor do certificado do destino não coincide");
                    std::process::exit(1);
                }
                if header.dst_key_algo != dst_key_type {
                    eprintln!("ERRO: Tipo da chave do certificado do destino não coincide");
                    std::process::exit(1);
                }
            }

            let mut data = Vec::new();
            if let Err(error) = input.read_to_end(&mut data) {
                eprintln!("ERRO: Falha ao ler dados a serem descriptografados: {error}");
                std::process::exit(1);
            };

            let sym_key = match dst_key.decrypt(&header.buffer_sym_key.value()) {
                Ok(sym_key) => sym_key,
                Err(error) => {
                    eprintln!("ERRO: Falha ao descriptografar chave simétrica: {error}");
                    std::process::exit(1);
                }
            };
            let aes = Aes256::new(&sym_key);
            let text = match aes.decrypt(&data) {
                Ok(text) => text,
                Err(error) => {
                    eprintln!("ERRO: Falha ao descriptografar os dados: {error}");
                    std::process::exit(1);
                }
            };
            if matches.get_flag("verifysign")
                && let Err(error) = src_cert_key.verify(&text, &header.buffer_hash.value())
            {
                eprintln!("ERRO: Assinatura inválida: {error}");
                std::process::exit(1);
            }

            let text: Vec<u8> = match header.special_treatment {
                SpecialTreatment::Compress | SpecialTreatment::ComrpessWithoutCrypt
                    if matches.get_flag("decompress") =>
                {
                    match decode_gzip(&text) {
                        Ok(text) => text,
                        Err(error) => {
                            eprintln!("ERRO: {error}");
                            std::process::exit(1);
                        }
                    }
                }
                _ => text,
            };

            if let Err(error) = output.write_all(&text) {
                eprintln!("ERRO: Falha ao escrever dados descriptografados: {error}");
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
