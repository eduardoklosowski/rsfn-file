use std::{
    fs::File,
    io::{self, Write},
    path::PathBuf,
};

use clap::{ArgAction, ArgMatches, Command, arg, command, value_parser};
use clap_complete::{Shell, generate};
use rsfn_file::{
    DecryptError, DecryptResult, EncryptError, EncryptResult, compress::Compressors,
    encode::Encoders, header,
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
                    arg!(-z --zip "Compacta arquivo com zip")
                        .action(ArgAction::SetTrue)
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
        format!("Falha na leitura do arquivo {filepath}\n{error}")
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

trait EncryptPrintable {
    fn print_certs_load_error(&self, err_output: &mut dyn io::Write) -> io::Result<bool>;
    fn print_cert_error(&self, err_output: &mut dyn io::Write) -> io::Result<bool>;
    fn print_read_content_error(&self, err_output: &mut dyn io::Write) -> io::Result<bool>;
    fn print_encrypt_error(&self, err_output: &mut dyn io::Write) -> io::Result<bool>;
    fn print_format_header_error(&self, err_output: &mut dyn io::Write) -> io::Result<bool>;
    fn print_data(
        &self,
        output: &mut dyn io::Write,
        err_output: &mut dyn io::Write,
    ) -> io::Result<bool>;

    fn print(
        &self,
        output: &mut dyn io::Write,
        err_output: &mut dyn io::Write,
        verify_cert: bool,
    ) -> io::Result<bool> {
        Ok(self.print_certs_load_error(err_output)?
            && (self.print_cert_error(err_output)? || !verify_cert)
            && self.print_read_content_error(err_output)?
            && self.print_encrypt_error(err_output)?
            && self.print_format_header_error(err_output)?
            && self.print_data(output, err_output)?)
    }
}

impl EncryptPrintable for Result<EncryptResult, EncryptError> {
    fn print_certs_load_error(&self, err_output: &mut dyn io::Write) -> io::Result<bool> {
        match self {
            Ok(..) => Ok(true),
            Err(error) => match error {
                EncryptError::SourceCert { .. }
                | EncryptError::SourceKey { .. }
                | EncryptError::DestinationCert { .. } => {
                    err_output.write_fmt(format_args!("ERRO: {error}\n"))?;
                    Ok(false)
                }
                EncryptError::ReadContent { .. }
                | EncryptError::Encode { .. }
                | EncryptError::Compress { .. }
                | EncryptError::EncryptContent { .. }
                | EncryptError::EncryptSymmetricKey { .. }
                | EncryptError::FormatHeader { .. } => Ok(true),
            },
        }
    }

    fn print_cert_error(&self, err_output: &mut dyn io::Write) -> io::Result<bool> {
        let cert_error = match self {
            Ok(result) => result.is_valid_cert().err(),
            Err(
                EncryptError::SourceCert { .. }
                | EncryptError::SourceKey { .. }
                | EncryptError::DestinationCert { .. },
            ) => None,
            Err(
                EncryptError::ReadContent { cert_error, .. }
                | EncryptError::Encode { cert_error, .. }
                | EncryptError::Compress { cert_error, .. }
                | EncryptError::EncryptContent { cert_error, .. }
                | EncryptError::EncryptSymmetricKey { cert_error, .. }
                | EncryptError::FormatHeader { cert_error, .. },
            ) => cert_error.clone(),
        };

        match cert_error {
            Some(error) => {
                err_output.write_fmt(format_args!("ERRO: {error}\n"))?;
                Ok(false)
            }
            None => Ok(true),
        }
    }

    fn print_read_content_error(&self, err_output: &mut dyn io::Write) -> io::Result<bool> {
        match self {
            Err(error @ EncryptError::ReadContent { .. }) => {
                err_output.write_fmt(format_args!("ERRO: {error}\n"))?;
                Ok(false)
            }
            Err(error @ EncryptError::Encode { .. }) => {
                err_output.write_fmt(format_args!("ERRO: {error}\n"))?;
                Ok(false)
            }
            Err(error @ EncryptError::Compress { .. }) => {
                err_output.write_fmt(format_args!("ERRO: {error}\n"))?;
                Ok(false)
            }
            _ => Ok(true),
        }
    }

    fn print_encrypt_error(&self, err_output: &mut dyn io::Write) -> io::Result<bool> {
        match self {
            Err(error @ EncryptError::EncryptContent { .. }) => {
                err_output.write_fmt(format_args!("ERRO: {error}\n"))?;
                Ok(false)
            }
            Err(error @ EncryptError::EncryptSymmetricKey { .. }) => {
                err_output.write_fmt(format_args!("ERRO: {error}\n"))?;
                Ok(false)
            }
            _ => Ok(true),
        }
    }

    fn print_format_header_error(&self, err_output: &mut dyn io::Write) -> io::Result<bool> {
        match self {
            Err(error @ EncryptError::FormatHeader { .. }) => {
                err_output.write_fmt(format_args!("ERRO: {error}\n"))?;
                Ok(false)
            }
            _ => Ok(true),
        }
    }

    fn print_data(
        &self,
        output: &mut dyn io::Write,
        err_output: &mut dyn io::Write,
    ) -> io::Result<bool> {
        if let Ok(result) = self {
            if !result.header().is_encrypted_content() {
                err_output.write_fmt(format_args!("ALERTA: Conteúdo não criptografado!\n"))?;
            }
            output.write_all(result.data())?;
        }
        Ok(true)
    }
}

fn encrypt_file(matches: &ArgMatches) -> Result<(), String> {
    let mut input = open_input(matches.get_one("input"))
        .map_err(|error| format!("Falha na entrada\n{error}"))?;
    let mut output = open_output(matches.get_one("output"))
        .map_err(|error| format!("Falha na saída\n{error}"))?;
    let mut err_output: Box<dyn io::Write> = Box::new(std::io::stderr());

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

    let verify_cert = matches.get_flag("verifycert");

    let mut encrypter = rsfn_file::actions::Encrypter::new();
    encrypter.set_special_treatment(
        matches
            .get_one::<header::SpecialTreatment>("specialtreatment")
            .cloned(),
    );
    encrypter.set_crypt(matches.get_flag("crypt"));
    encrypter.set_compressor(match (matches.get_flag("zip"), matches.get_flag("gzip")) {
        (true, _) => Compressors::Zip,
        (false, true) => Compressors::Gzip,
        (false, false) => Compressors::Plain,
    });
    encrypter.set_encoder(match matches.get_flag("encode") {
        true => Encoders::default(),
        false => Encoders::Plain,
    });
    let result = encrypter.encrypt(&src_cert, &src_key, &dst_cert, &mut input);
    result
        .print(&mut output, &mut err_output, verify_cert)
        .map_err(|error| error.to_string())?;

    Ok(())
}

trait DecryptPrintable {
    fn print_certs_load_error(&self, err_output: &mut dyn io::Write) -> io::Result<bool>;
    fn print_header(&self, err_output: &mut dyn io::Write) -> io::Result<bool>;
    fn print_cert_error(&self, err_output: &mut dyn io::Write) -> io::Result<bool>;
    fn print_read_content_error(&self, err_output: &mut dyn io::Write) -> io::Result<bool>;
    fn print_decrypt_error(&self, err_output: &mut dyn io::Write) -> io::Result<bool>;
    fn print_signature_error(&self, err_output: &mut dyn io::Write) -> io::Result<bool>;
    fn print_data(
        &self,
        output: &mut dyn io::Write,
        err_output: &mut dyn io::Write,
    ) -> io::Result<bool>;

    fn print(
        &self,
        output: &mut dyn io::Write,
        err_output: &mut dyn io::Write,
        verify_header: bool,
        verify_cert: bool,
        verify_sign: bool,
    ) -> io::Result<bool> {
        Ok(self.print_certs_load_error(err_output)?
            && (self.print_header(err_output)? || !verify_header)
            && (self.print_cert_error(err_output)? || !verify_cert)
            && self.print_read_content_error(err_output)?
            && self.print_decrypt_error(err_output)?
            && (self.print_signature_error(err_output)? || !verify_sign)
            && self.print_data(output, err_output)?)
    }
}

impl DecryptPrintable for Result<DecryptResult, DecryptError> {
    fn print_certs_load_error(&self, err_output: &mut dyn io::Write) -> io::Result<bool> {
        match self {
            Ok(..) => Ok(true),
            Err(error) => match error {
                DecryptError::SourceCert { .. }
                | DecryptError::DestinationCert { .. }
                | DecryptError::DestinationKey { .. } => {
                    err_output.write_fmt(format_args!("ERRO: {error}\n"))?;
                    Ok(false)
                }
                DecryptError::ReadHeader { .. }
                | DecryptError::ReadContent { .. }
                | DecryptError::DecryptSymmetricKey { .. }
                | DecryptError::DecryptContent { .. }
                | DecryptError::Decompress { .. }
                | DecryptError::Decode { .. } => Ok(true),
            },
        }
    }

    fn print_header(&self, err_output: &mut dyn io::Write) -> io::Result<bool> {
        let header = match self {
            Ok(a) => a.header(),
            Err(
                DecryptError::SourceCert { .. }
                | DecryptError::DestinationCert { .. }
                | DecryptError::DestinationKey { .. },
            ) => return Ok(true),
            Err(error @ DecryptError::ReadHeader { .. }) => {
                err_output.write_fmt(format_args!("ERRO: {error}\n"))?;
                return Ok(false);
            }
            Err(
                DecryptError::ReadContent { header, .. }
                | DecryptError::DecryptSymmetricKey { header, .. }
                | DecryptError::DecryptContent { header, .. }
                | DecryptError::Decompress { header, .. }
                | DecryptError::Decode { header, .. },
            ) => header,
        };
        err_output.write_fmt(format_args!("{header}\n"))?;

        match header.is_valid() {
            Ok(()) => Ok(true),
            Err(error) => {
                err_output.write_fmt(format_args!(
                    "ERRO: Cabeçalho de segurança inválido\nERRO: {error}\n"
                ))?;
                Ok(false)
            }
        }
    }

    fn print_cert_error(&self, err_output: &mut dyn io::Write) -> io::Result<bool> {
        let cert_error = match self {
            Ok(result) => result.is_valid_cert().err(),
            Err(
                DecryptError::SourceCert { .. }
                | DecryptError::DestinationCert { .. }
                | DecryptError::DestinationKey { .. }
                | DecryptError::ReadHeader { .. },
            ) => None,
            Err(
                DecryptError::ReadContent { cert_error, .. }
                | DecryptError::DecryptSymmetricKey { cert_error, .. }
                | DecryptError::DecryptContent { cert_error, .. }
                | DecryptError::Decompress { cert_error, .. }
                | DecryptError::Decode { cert_error, .. },
            ) => cert_error.clone(),
        };

        match cert_error {
            Some(error) => {
                err_output.write_fmt(format_args!("ERRO: {error}\n"))?;
                Ok(false)
            }
            None => Ok(true),
        }
    }

    fn print_read_content_error(&self, err_output: &mut dyn io::Write) -> io::Result<bool> {
        match self {
            Err(error @ DecryptError::ReadContent { .. }) => {
                err_output.write_fmt(format_args!("ERRO: {error}\n"))?;
                Ok(false)
            }
            _ => Ok(true),
        }
    }

    fn print_decrypt_error(&self, err_output: &mut dyn io::Write) -> io::Result<bool> {
        let error = match self {
            Err(error @ DecryptError::DecryptSymmetricKey { .. }) => error,
            Err(error @ DecryptError::DecryptContent { .. }) => error,
            Ok(_) | Err(_) => return Ok(true),
        };

        err_output.write_fmt(format_args!("ERRO: {error}\n"))?;
        Ok(false)
    }

    fn print_signature_error(&self, err_output: &mut dyn io::Write) -> io::Result<bool> {
        let signature_error = match self {
            Ok(result) => result.is_valid_signature().err(),
            Err(
                DecryptError::SourceCert { .. }
                | DecryptError::DestinationCert { .. }
                | DecryptError::DestinationKey { .. }
                | DecryptError::ReadHeader { .. }
                | DecryptError::ReadContent { .. }
                | DecryptError::DecryptSymmetricKey { .. }
                | DecryptError::DecryptContent { .. },
            ) => None,
            Err(
                DecryptError::Decompress {
                    signature_error, ..
                }
                | DecryptError::Decode {
                    signature_error, ..
                },
            ) => signature_error.clone(),
        };

        match signature_error {
            Some(error) => {
                err_output.write_fmt(format_args!("ERRO: {error}\n"))?;
                Ok(false)
            }
            None => Ok(true),
        }
    }

    fn print_data(
        &self,
        output: &mut dyn io::Write,
        err_output: &mut dyn io::Write,
    ) -> io::Result<bool> {
        let (header, data, status) = match self {
            Ok(result) => (result.header(), result.data(), true),
            Err(
                DecryptError::Decompress { header, data, .. }
                | DecryptError::Decode { header, data, .. },
            ) => (header, data, false),
            Err(_) => {
                return Ok(true);
            }
        };
        if !header.is_encrypted_content() {
            err_output.write_fmt(format_args!("ALERTA: Conteúdo não criptografado!\n"))?;
        }
        if let Err(error) = self {
            err_output.write_fmt(format_args!("ERRO: {error}\n"))?;
        }
        output.write_all(data)?;
        Ok(status)
    }
}

fn decrypt_file(matches: &ArgMatches) -> Result<(), String> {
    let mut input = open_input(matches.get_one("input"))
        .map_err(|error| format!("Falha na entrada\n{error}"))?;
    let mut output = open_output(matches.get_one("output"))
        .map_err(|error| format!("Falha na saída\n{error}"))?;
    let mut err_output: Box<dyn io::Write> = Box::new(std::io::stderr());

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

    let verify_header = matches.get_flag("verifyheader");
    let verify_cert = matches.get_flag("verifycert");
    let verify_sign = matches.get_flag("verifysign");

    let mut decrypter = rsfn_file::actions::Decrypter::new();
    decrypter.set_decompress(matches.get_flag("decompress"));
    decrypter.set_decode(matches.get_flag("decode"));
    let result = decrypter.decrypt(&src_cert, &dst_cert, &dst_key, &mut input);
    result
        .print(
            &mut output,
            &mut err_output,
            verify_header,
            verify_cert,
            verify_sign,
        )
        .map_err(|error| error.to_string())?;

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

#[cfg(test)]
mod tests {
    use rand::{
        RngExt,
        distr::{Alphanumeric, SampleString},
    };
    use rsfn_file::{CertError, SignatureError};

    use super::*;

    macro_rules! test_print_encrypt {
        ($sut_value:expr, $expected_return_value:expr, $expected_output_value:expr, $expected_err_output_value:expr) => {
            let mut output = io::Cursor::new(Vec::new());
            let mut err_output = io::Cursor::new(Vec::new());

            let sut = $sut_value;
            let returned = sut.print(&mut output, &mut err_output, true);

            let output = output.into_inner();
            let err_output = String::from_utf8_lossy(err_output.get_ref());

            assert_eq!(returned.unwrap(), $expected_return_value, "return value");
            assert_eq!(output, $expected_output_value, "stdout value");
            assert_eq!(err_output, $expected_err_output_value, "stderr value");
        };
    }

    #[test]
    fn print_encrypt_with_source_cert_error() {
        let mut rng = rand::rng();

        let error = Alphanumeric.sample_string(&mut rng, 10);

        let sut = Err(EncryptError::SourceCert {
            error: error.clone(),
        });
        test_print_encrypt!(
            sut,
            false,
            Vec::new(),
            format!("ERRO: Falha no certificado da origem\n{error}\n")
        );
    }

    #[test]
    fn print_encrypt_with_destination_key_error() {
        let mut rng = rand::rng();

        let error = Alphanumeric.sample_string(&mut rng, 10);

        let sut = Err(EncryptError::SourceKey {
            error: error.clone(),
        });
        test_print_encrypt!(
            sut,
            false,
            Vec::new(),
            format!("ERRO: Falha na chave privada da origem\n{error}\n")
        );
    }

    #[test]
    fn print_encrypt_with_destination_cert_error() {
        let mut rng = rand::rng();

        let error = Alphanumeric.sample_string(&mut rng, 10);

        let sut = Err(EncryptError::DestinationCert {
            error: error.clone(),
        });
        test_print_encrypt!(
            sut,
            false,
            Vec::new(),
            format!("ERRO: Falha no certificado do destino\n{error}\n")
        );
    }

    #[test]
    fn print_encrypt_with_read_content_error_and_cert_error() {
        let mut rng = rand::rng();

        let error = Alphanumeric.sample_string(&mut rng, 10);

        let sut = Err(EncryptError::ReadContent {
            error: error.clone(),
            cert_error: Some(CertError::MismatchDestinationCert),
        });
        test_print_encrypt!(
            sut,
            false,
            Vec::new(),
            format!("ERRO: Certificado do destino não coincide\n")
        );
    }

    #[test]
    fn print_encrypt_with_read_content_error() {
        let mut rng = rand::rng();

        let error = Alphanumeric.sample_string(&mut rng, 10);

        let sut = Err(EncryptError::ReadContent {
            error: error.clone(),
            cert_error: None,
        });
        test_print_encrypt!(
            sut,
            false,
            Vec::new(),
            format!("ERRO: Falha ao ler dados a serem criptografados\n{error}\n")
        );
    }

    #[test]
    fn print_encrypt_with_encode_error() {
        let mut rng = rand::rng();

        let error = Alphanumeric.sample_string(&mut rng, 10);

        let sut = Err(EncryptError::Encode {
            error: error.clone(),
            cert_error: None,
        });
        test_print_encrypt!(
            sut,
            false,
            Vec::new(),
            format!("ERRO: Falha no encode dos dados UTF-8\n{error}\n")
        );
    }

    #[test]
    fn print_encrypt_with_compress_error() {
        let mut rng = rand::rng();

        let error = Alphanumeric.sample_string(&mut rng, 10);

        let sut = Err(EncryptError::Compress {
            error: error.clone(),
            cert_error: None,
        });
        test_print_encrypt!(
            sut,
            false,
            Vec::new(),
            format!("ERRO: Falha na compactação do arquivo\n{error}\n")
        );
    }

    #[test]
    fn print_encrypt_with_encrypt_content_error() {
        let mut rng = rand::rng();

        let error = Alphanumeric.sample_string(&mut rng, 10);

        let sut = Err(EncryptError::EncryptContent {
            error: error.clone(),
            cert_error: None,
        });
        test_print_encrypt!(
            sut,
            false,
            Vec::new(),
            format!("ERRO: Falha na criptografia do arquivo\n{error}\n")
        );
    }

    #[test]
    fn print_encrypt_with_encrypt_symmetric_key_error() {
        let mut rng = rand::rng();

        let error = Alphanumeric.sample_string(&mut rng, 10);

        let sut = Err(EncryptError::EncryptSymmetricKey {
            error: error.clone(),
            cert_error: None,
        });
        test_print_encrypt!(
            sut,
            false,
            Vec::new(),
            format!("ERRO: Falha na criptografia da chave simétrica\n{error}\n")
        );
    }

    #[test]
    fn print_encrypt_with_encrypt_format_header_error() {
        let mut rng = rand::rng();

        let error = Alphanumeric.sample_string(&mut rng, 10);

        let sut = Err(EncryptError::FormatHeader {
            error: error.clone(),
            cert_error: None,
        });
        test_print_encrypt!(
            sut,
            false,
            Vec::new(),
            format!("ERRO: Erro ao formatar o cabeçalho de segurança\n{error}\n")
        );
    }

    #[test]
    fn print_encrypt_with_success() {
        let mut rng = rand::rng();

        let header = header::Header {
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
            dst_cert_serial: [b'1'; 32].into(),
            src_pc_cert: header::PcCert::SpbSerpro,
            src_cert_serial: [b'1'; 32].into(),
            buffer_sym_key: [1; 256].into(),
            buffer_hash: [1; 256].into(),
        };
        let content: Vec<_> = (0..rng.random_range(10..20))
            .map(|_| rng.random())
            .collect();

        let sut = Ok(EncryptResult::new(header.clone(), None, content.clone()));
        test_print_encrypt!(sut, true, content, format!(""));
    }

    macro_rules! test_print_decrypt {
        ($sut_value:expr, $expected_return_value:expr, $expected_output_value:expr, $expected_err_output_value:expr) => {
            let mut output = io::Cursor::new(Vec::new());
            let mut err_output = io::Cursor::new(Vec::new());

            let sut = $sut_value;
            let returned = sut.print(&mut output, &mut err_output, true, true, true);

            let output = output.into_inner();
            let err_output = String::from_utf8_lossy(err_output.get_ref());

            assert_eq!(returned.unwrap(), $expected_return_value, "return value");
            assert_eq!(output, $expected_output_value, "stdout value");
            assert_eq!(err_output, $expected_err_output_value, "stderr value");
        };
    }

    #[test]
    fn print_decrypt_with_source_cert_error() {
        let mut rng = rand::rng();

        let error = Alphanumeric.sample_string(&mut rng, 10);

        let sut = Err(DecryptError::SourceCert {
            error: error.clone(),
        });
        test_print_decrypt!(
            sut,
            false,
            Vec::new(),
            format!("ERRO: Falha no certificado da origem\n{error}\n")
        );
    }

    #[test]
    fn print_decrypt_with_destination_cert_error() {
        let mut rng = rand::rng();

        let error = Alphanumeric.sample_string(&mut rng, 10);

        let sut = Err(DecryptError::DestinationCert {
            error: error.clone(),
        });
        test_print_decrypt!(
            sut,
            false,
            Vec::new(),
            format!("ERRO: Falha no certificado do destino\n{error}\n")
        );
    }

    #[test]
    fn print_decrypt_with_destination_key_error() {
        let mut rng = rand::rng();

        let error = Alphanumeric.sample_string(&mut rng, 10);

        let sut = Err(DecryptError::DestinationKey {
            error: error.clone(),
        });
        test_print_decrypt!(
            sut,
            false,
            Vec::new(),
            format!("ERRO: Falha na chave privada do destino\n{error}\n")
        );
    }

    #[test]
    fn print_decrypt_with_read_header_error() {
        let mut rng = rand::rng();

        let error = Alphanumeric.sample_string(&mut rng, 10);

        let sut = Err(DecryptError::ReadHeader {
            error: error.clone(),
        });
        test_print_decrypt!(
            sut,
            false,
            Vec::new(),
            format!("ERRO: Falha na leitura do cabelho de segurança\n{error}\n")
        );
    }

    #[test]
    fn print_decrypt_with_read_content_error_and_invalid_header() {
        let mut rng = rand::rng();

        let error = Alphanumeric.sample_string(&mut rng, 10);
        let header = header::Header {
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
            dst_cert_serial: [0; 32].into(),
            src_pc_cert: header::PcCert::SpbSerpro,
            src_cert_serial: [0; 32].into(),
            buffer_sym_key: [1; 256].into(),
            buffer_hash: [1; 256].into(),
        };

        let sut = Err(DecryptError::ReadContent {
            error: error.clone(),
            header: header.clone(),
            cert_error: None,
        });
        test_print_decrypt!(
            sut,
            false,
            Vec::new(),
            format!(
                "{header}\nERRO: Cabeçalho de segurança inválido\nERRO: C11 inválido, C13 inválido\n"
            )
        );
    }

    #[test]
    fn print_decrypt_with_read_content_error_and_cert_error() {
        let mut rng = rand::rng();

        let error = Alphanumeric.sample_string(&mut rng, 10);
        let header = header::Header {
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
            dst_cert_serial: [b'1'; 32].into(),
            src_pc_cert: header::PcCert::SpbSerpro,
            src_cert_serial: [b'1'; 32].into(),
            buffer_sym_key: [1; 256].into(),
            buffer_hash: [1; 256].into(),
        };

        let sut = Err(DecryptError::ReadContent {
            error: error.clone(),
            header: header.clone(),
            cert_error: Some(CertError::MismatchSourceCert),
        });
        test_print_decrypt!(
            sut,
            false,
            Vec::new(),
            format!("{header}\nERRO: Certificado da origem não coincide\n")
        );
    }

    #[test]
    fn print_decrypt_with_read_content_error() {
        let mut rng = rand::rng();

        let error = Alphanumeric.sample_string(&mut rng, 10);
        let header = header::Header {
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
            dst_cert_serial: [b'1'; 32].into(),
            src_pc_cert: header::PcCert::SpbSerpro,
            src_cert_serial: [b'1'; 32].into(),
            buffer_sym_key: [1; 256].into(),
            buffer_hash: [1; 256].into(),
        };

        let sut = Err(DecryptError::ReadContent {
            error: error.clone(),
            header: header.clone(),
            cert_error: None,
        });
        test_print_decrypt!(
            sut,
            false,
            Vec::new(),
            format!("{header}\nERRO: Falha ao ler dados a serem descriptografados\n{error}\n")
        );
    }

    #[test]
    fn print_decrypt_with_decrypt_symmetric_key_error() {
        let mut rng = rand::rng();

        let error = Alphanumeric.sample_string(&mut rng, 10);
        let header = header::Header {
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
            dst_cert_serial: [b'1'; 32].into(),
            src_pc_cert: header::PcCert::SpbSerpro,
            src_cert_serial: [b'1'; 32].into(),
            buffer_sym_key: [1; 256].into(),
            buffer_hash: [1; 256].into(),
        };

        let sut = Err(DecryptError::DecryptSymmetricKey {
            error: error.clone(),
            header: header.clone(),
            cert_error: None,
        });
        test_print_decrypt!(
            sut,
            false,
            Vec::new(),
            format!("{header}\nERRO: Falha ao descriptografar chave simétrica\n{error}\n")
        );
    }

    #[test]
    fn print_decrypt_with_decrypt_content_error() {
        let mut rng = rand::rng();

        let error = Alphanumeric.sample_string(&mut rng, 10);
        let header = header::Header {
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
            dst_cert_serial: [b'1'; 32].into(),
            src_pc_cert: header::PcCert::SpbSerpro,
            src_cert_serial: [b'1'; 32].into(),
            buffer_sym_key: [1; 256].into(),
            buffer_hash: [1; 256].into(),
        };

        let sut = Err(DecryptError::DecryptContent {
            error: error.clone(),
            header: header.clone(),
            cert_error: None,
        });
        test_print_decrypt!(
            sut,
            false,
            Vec::new(),
            format!("{header}\nERRO: Falha ao descriptografar os dados\n{error}\n")
        );
    }

    #[test]
    fn print_decrypt_with_decompress_error() {
        let mut rng = rand::rng();

        let error = Alphanumeric.sample_string(&mut rng, 10);
        let header = header::Header {
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
            dst_cert_serial: [b'1'; 32].into(),
            src_pc_cert: header::PcCert::SpbSerpro,
            src_cert_serial: [b'1'; 32].into(),
            buffer_sym_key: [1; 256].into(),
            buffer_hash: [1; 256].into(),
        };
        let data: Vec<_> = (0..rng.random_range(10..20))
            .map(|_| rng.random())
            .collect();

        let sut = Err(DecryptError::Decompress {
            error: error.clone(),
            header: header.clone(),
            cert_error: None,
            signature_error: None,
            data: data.clone(),
        });
        test_print_decrypt!(
            sut,
            false,
            data,
            format!("{header}\nERRO: Falha na descompactação\n{error}\n")
        );
    }

    #[test]
    fn print_decrypt_with_decompress_error_and_not_crypt() {
        let mut rng = rand::rng();

        let error = Alphanumeric.sample_string(&mut rng, 10);
        let header = header::Header {
            len: header::HeaderLen::Default,
            version: header::ProtocolVersion::Version3,
            error: header::ErrorCode::NoError,
            special_treatment: header::SpecialTreatment::NotCrypt,
            reserved: header::Reserved::NoValue,
            dst_key_algo: header::AsymmetricKeyAlgo::RSA2048,
            sym_key_algo: header::SymmetricKeyAlgo::Aes,
            src_key_algo: header::AsymmetricKeyAlgo::RSA2048,
            hash_algo: header::HashAlgo::SHA256,
            dst_pc_cert: header::PcCert::SpbSerpro,
            dst_cert_serial: [b'1'; 32].into(),
            src_pc_cert: header::PcCert::SpbSerpro,
            src_cert_serial: [b'1'; 32].into(),
            buffer_sym_key: [1; 256].into(),
            buffer_hash: [1; 256].into(),
        };
        let data: Vec<_> = (0..rng.random_range(10..20))
            .map(|_| rng.random())
            .collect();

        let sut = Err(DecryptError::Decompress {
            error: error.clone(),
            header: header.clone(),
            cert_error: None,
            signature_error: None,
            data: data.clone(),
        });
        test_print_decrypt!(
            sut,
            false,
            data,
            format!(
                "{header}\nALERTA: Conteúdo não criptografado!\nERRO: Falha na descompactação\n{error}\n"
            )
        );
    }

    #[test]
    fn print_decrypt_with_decompress_error_and_signature_error() {
        let mut rng = rand::rng();

        let error = Alphanumeric.sample_string(&mut rng, 10);
        let signature_error = Alphanumeric.sample_string(&mut rng, 10);
        let header = header::Header {
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
            dst_cert_serial: [b'1'; 32].into(),
            src_pc_cert: header::PcCert::SpbSerpro,
            src_cert_serial: [b'1'; 32].into(),
            buffer_sym_key: [1; 256].into(),
            buffer_hash: [1; 256].into(),
        };
        let data: Vec<_> = (0..rng.random_range(10..20))
            .map(|_| rng.random())
            .collect();

        let sut = Err(DecryptError::Decompress {
            error: error.clone(),
            header: header.clone(),
            cert_error: None,
            signature_error: Some(SignatureError::Invalid {
                error: signature_error.clone(),
            }),
            data,
        });
        test_print_decrypt!(
            sut,
            false,
            Vec::new(),
            format!("{header}\nERRO: Assinatura dos dados inválida\n{signature_error}\n")
        );
    }

    #[test]
    fn print_decrypt_with_decode_error() {
        let mut rng = rand::rng();

        let error = Alphanumeric.sample_string(&mut rng, 10);
        let header = header::Header {
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
            dst_cert_serial: [b'1'; 32].into(),
            src_pc_cert: header::PcCert::SpbSerpro,
            src_cert_serial: [b'1'; 32].into(),
            buffer_sym_key: [1; 256].into(),
            buffer_hash: [1; 256].into(),
        };
        let data: Vec<_> = (0..rng.random_range(10..20))
            .map(|_| rng.random())
            .collect();

        let sut = Err(DecryptError::Decode {
            error: error.clone(),
            header: header.clone(),
            cert_error: None,
            signature_error: None,
            data: data.clone(),
        });
        test_print_decrypt!(
            sut,
            false,
            data,
            format!("{header}\nERRO: Falha no decode dos dados\n{error}\n")
        );
    }

    #[test]
    fn print_decrypt_with_success() {
        let mut rng = rand::rng();

        let header = header::Header {
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
            dst_cert_serial: [b'1'; 32].into(),
            src_pc_cert: header::PcCert::SpbSerpro,
            src_cert_serial: [b'1'; 32].into(),
            buffer_sym_key: [1; 256].into(),
            buffer_hash: [1; 256].into(),
        };
        let content: Vec<_> = (0..rng.random_range(10..20))
            .map(|_| rng.random())
            .collect();

        let sut = Ok(DecryptResult::new(
            header.clone(),
            None,
            None,
            content.clone(),
        ));
        test_print_decrypt!(sut, true, content, format!("{header}\n"));
    }
}
