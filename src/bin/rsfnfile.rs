use std::{
    fs::File,
    io::{self, Read, Write},
    path::PathBuf,
};

use clap::{ArgAction, ArgMatches, Command, arg, command, value_parser};
use clap_complete::{Shell, generate};
use rsfn_file::{
    cert::Certificate,
    ciphers::{Aes256, RsaPrivate, RsaPublic},
    compress::Compressors,
    encode::Encoders,
    header,
};

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

fn load_certificate(
    filepath: &PathBuf,
) -> Result<(Certificate, header::AsymmetricKeyAlgo, RsaPublic), String> {
    let content =
        std::fs::read(filepath).map_err(|error| format!("Falha na leitura do arquivo: {error}"))?;
    let certificate =
        Certificate::load(&content).map_err(|error| format!("Certificado inválido: {error}"))?;
    let key_type = certificate
        .key_type()
        .map_err(|error| format!("Falha no tipo da chave do certificado: {error}"))?;
    let certificate_key = match key_type {
        header::AsymmetricKeyAlgo::RSA1024 | header::AsymmetricKeyAlgo::RSA2048 => certificate
            .rsa_pub_key()
            .map_err(|error| format!("Falha ao carregar chave RSA: {error}"))?,
        _ => Err(format!(
            "Sem implementação para chave {}",
            key_type.describe_value()
        ))?,
    };
    Ok((certificate, key_type, certificate_key))
}

fn load_key(filepath: &PathBuf) -> Result<RsaPrivate, String> {
    let content = std::fs::read_to_string(filepath)
        .map_err(|error| format!("Falha na leitura do arquivo: {error}"))?;
    let key = RsaPrivate::load_pem(&content).map_err(|error| format!("Chave inválida: {error}"))?;
    Ok(key)
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

fn encrypt_file(matches: &ArgMatches) -> Result<(), String> {
    let mut input = open_input(matches.get_one("input"))
        .map_err(|error| format!("Falha na entrada\n{error}"))?;
    let mut output = open_output(matches.get_one("output"))
        .map_err(|error| format!("Falha na saída\n{error}"))?;

    let (src_cert, src_key_type, src_cert_key) = load_certificate(
        matches
            .get_one("src_cert")
            .expect("Argumento do certificado da origem faltando"),
    )
    .map_err(|error| format!("Falha no certificado da origem\n{error}"))?;
    let src_key = load_key(
        matches
            .get_one("src_key")
            .expect("Argumento da chave privada da origem faltando"),
    )
    .map_err(|error| format!("Falha na chave privada da origem\n{error}"))?;
    if matches.get_flag("verifycert") && !src_key.check_public_key(&src_cert_key) {
        Err("Chave privada da origem não coresponde ao seu certificado")?;
    }

    let (dst_cert, dst_key_type, dst_cert_key) = load_certificate(
        matches
            .get_one("dst_cert")
            .expect("Argumento do certificado do destino faltando"),
    )
    .map_err(|error| format!("Falha no certificado do destino\n{error}"))?;

    let mut data = Vec::new();
    input
        .read_to_end(&mut data)
        .map_err(|error| format!("Falha ao ler dados a serem criptografados\n{error}"))?;
    let encoder = match matches.get_flag("encode") {
        true => Encoders::default(),
        false => Encoders::Plain,
    };
    let data = encoder
        .init()
        .encode(&data)
        .map_err(|error| format!("Falha no encode dos dados UTF-8\n{error}"))?;
    let compressor = match matches.get_flag("gzip") {
        true => Compressors::Gzip,
        false => Compressors::Plain,
    };
    let data = compressor
        .init()
        .compress(&data)
        .map_err(|error| format!("Falha na compactação do arquivo\n{error}"))?;

    let (cipher_sym_key, cipher_data) = if matches.get_flag("crypt") {
        let aes = Aes256::generate_new_key();
        let cipher_data = aes
            .encrypt(&data)
            .map_err(|error| format!("Falha na criptografia do arquivo\n{error}"))?;
        let cipher_sym_key = dst_cert_key
            .encrypt(&aes.export_key())
            .map_err(|error| format!("Falha na criptografia da chave simétrica\n{error}"))?;
        (cipher_sym_key, cipher_data)
    } else {
        (Vec::from([0; 256]), data.clone())
    };
    let sign = src_key.sign(&data);

    let special_treatment = match matches.get_one::<header::SpecialTreatment>("specialtreatment") {
        Some(value) => value.clone(),
        None => match compressor {
            Compressors::Plain => header::SpecialTreatment::NotCompress,
            _ => header::SpecialTreatment::Compress,
        },
    };

    let header = header::Header {
        len: header::HeaderLen::Default,
        version: header::ProtocolVersion::Version3,
        error: header::ErrorCode::NoError,
        special_treatment,
        reserved: header::Reserved::NoValue,
        dst_key_algo: dst_key_type,
        sym_key_algo: header::SymmetricKeyAlgo::Aes,
        src_key_algo: src_key_type,
        hash_algo: header::HashAlgo::SHA256,
        dst_pc_cert: dst_cert.issuer(),
        dst_cert_serial: dst_cert.serial(),
        src_pc_cert: src_cert.issuer(),
        src_cert_serial: src_cert.serial(),
        buffer_sym_key: cipher_sym_key
            .try_into()
            .expect("Tamanho da chave simétrica incorreto"),
        buffer_hash: sign.try_into().expect("Tamanho da assinatura incorreto"),
    };

    output
        .write_all(&header.to_bytes())
        .map_err(|error| format!("Falha ao escrever cabeçalho de segurança\n{error}"))?;
    output
        .write_all(&cipher_data)
        .map_err(|error| format!("Falha ao escrever os dados criptografados\n{error}"))?;

    Ok(())
}

fn decrypt_file(matches: &ArgMatches) -> Result<(), String> {
    let mut input = open_input(matches.get_one("input"))
        .map_err(|error| format!("Falha na entrada\n{error}"))?;
    let mut output = open_output(matches.get_one("output"))
        .map_err(|error| format!("Falha na saída\n{error}"))?;

    let (src_cert, src_key_type, src_cert_key) = load_certificate(
        matches
            .get_one("src_cert")
            .expect("Argumento do certificado da origem faltando"),
    )
    .map_err(|error| format!("Falha no certificado da origem\n{error}"))?;

    let (dst_cert, dst_key_type, dst_cert_key) = load_certificate(
        matches
            .get_one("dst_cert")
            .expect("Argumento do certificado do destino faltando"),
    )
    .map_err(|error| format!("Falha no certificado do destino\n{error}"))?;
    let dst_key = load_key(
        matches
            .get_one("dst_key")
            .expect("Argumento da chave privada do destino faltando"),
    )
    .map_err(|error| format!("Falha na chave privada do destino\n{error}"))?;
    if matches.get_flag("verifycert") && !dst_key.check_public_key(&dst_cert_key) {
        Err("Chave privada do destino não coresponde ao seu certificado")?;
    }

    let header = header::Header::read_from_file(&mut input)
        .map_err(|error| format!("Falha na leitura do cabelho de segurança\n{error}"))?;
    if matches.get_flag("verifyheader") {
        header
            .is_valid()
            .map_err(|error| format!("Cabeçalho de segurança inválido\n{error}"))?;
    }
    if matches.get_flag("verifycert") {
        if header.src_cert_serial != src_cert.serial() {
            Err("Certificado da origem não coincide")?;
        }
        if header.src_pc_cert != src_cert.issuer() {
            Err("Emissor do certificado da origem não coincide")?;
        }
        if header.src_key_algo != src_key_type {
            Err("Tipo da chave do certificado da origem não coincide")?;
        }

        if header.dst_cert_serial != dst_cert.serial() {
            Err("Certificado do destino não coincide")?;
        }
        if header.dst_pc_cert != dst_cert.issuer() {
            Err("Emissor do certificado do destino não coincide")?;
        }
        if header.dst_key_algo != dst_key_type {
            Err("Tipo da chave do certificado do destino não coincide")?;
        }
    }

    let mut data = Vec::new();
    input
        .read_to_end(&mut data)
        .map_err(|error| format!("Falha ao ler dados a serem descriptografados\n{error}"))?;

    let buffer_sym_key = header.buffer_sym_key.value();
    let plain_data = if buffer_sym_key.iter().any(|&byte| byte != 0) {
        let sym_key = dst_key
            .decrypt(&buffer_sym_key)
            .map_err(|error| format!("Falha ao descriptografar chave simétrica\n{error}"))?;
        let aes = Aes256::new(&sym_key);
        aes.decrypt(&data)
            .map_err(|error| format!("Falha ao descriptografar os dados\n{error}"))?
    } else {
        data
    };
    if matches.get_flag("verifysign") {
        src_cert_key
            .verify(&plain_data, &header.buffer_hash.value())
            .map_err(|error| format!("Assinatura dos dados inválida\n{error}"))?;
    }

    let plain_data: Vec<u8> = match header.special_treatment {
        header::SpecialTreatment::Compress | header::SpecialTreatment::CompressWithoutCrypt
            if matches.get_flag("decompress") =>
        {
            Compressors::try_decompress(&plain_data)
                .map_err(|error| format!("Falha na descompactação do gzip\n{error}"))?
        }
        _ => plain_data,
    };
    let decoder = match matches.get_flag("decode") {
        true => Encoders::default(),
        false => Encoders::Plain,
    };
    let plain_data = match matches.get_flag("decompress") {
        true => decoder
            .init()
            .decode(&plain_data)
            .map_err(|error| format!("Falha no decode dos dados\n{error}"))?,
        false => plain_data,
    };

    output
        .write_all(&plain_data)
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
