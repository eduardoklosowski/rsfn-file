use std::io;

use crate::{
    cert::load_cert_and_key,
    ciphers::{Aes256, load_key},
    compress::Compressors,
    encode::Encoders,
    header,
};

pub fn load_header<R: io::Read>(file: &mut R) -> Result<header::Header, String> {
    header::Header::read_from_file(file)
        .map_err(|error| format!("Falha na leitura do cabeçalho de segurança\n{error}"))
}

#[derive(Debug)]
pub struct EncryptParams {
    pub special_treatment: Option<header::SpecialTreatment>,
    pub crypt: bool,
    pub compressor: Compressors,
    pub encoder: Encoders,
    pub verify_certs: bool,
}

impl Default for EncryptParams {
    fn default() -> Self {
        Self {
            special_treatment: None,
            crypt: true,
            compressor: Compressors::default(),
            encoder: Encoders::default(),
            verify_certs: true,
        }
    }
}

pub fn encrypt<R: io::Read>(
    src_cert: &[u8],
    src_key: &[u8],
    dst_cert: &[u8],
    params: &EncryptParams,
    file: &mut R,
) -> Result<Vec<u8>, String> {
    let (src_cert, src_key_type, src_cert_key) = load_cert_and_key(src_cert)
        .map_err(|error| format!("Falha no certificado da origem\n{error}"))?;
    let src_key =
        load_key(src_key).map_err(|error| format!("Falha na chave privada da origem\n{error}"))?;
    if params.verify_certs && !src_key.check_public_key(&src_cert_key) {
        Err("Chave privada da origem não coresponde ao seu certificado")?;
    }

    let (dst_cert, dst_key_type, dst_cert_key) = load_cert_and_key(dst_cert)
        .map_err(|error| format!("Falha no certificado do destino\n{error}"))?;

    let mut data = Vec::new();
    file.read_to_end(&mut data)
        .map_err(|error| format!("Falha ao ler dados a serem descriptografados\n{error}"))?;
    let data = params
        .encoder
        .init()
        .encode(&data)
        .map_err(|error| format!("Falha no encode dos dados UTF-8\n{error}"))?;
    let data = params
        .compressor
        .init()
        .compress(&data)
        .map_err(|error| format!("Falha na compactação do arquivo\n{error}"))?;

    let (cipher_sym_key, cipher_data) = if params.crypt {
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

    let special_treatment = match &params.special_treatment {
        Some(value) => value.clone(),
        None => match params.compressor {
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
            .map_err(|_| "Tamanho da chave simétrica incorreto")?,
        buffer_hash: sign
            .try_into()
            .map_err(|_| "Tamanho da assinatura incorreto")?,
    };

    let mut output = header.to_bytes();
    output.extend(cipher_data);
    Ok(output)
}

#[derive(Debug)]
pub struct DecryptParams {
    pub decompress: bool,
    pub decode: bool,
    pub verify_header: bool,
    pub verify_certs: bool,
    pub verify_sign: bool,
}

impl Default for DecryptParams {
    fn default() -> Self {
        Self {
            decompress: true,
            decode: true,
            verify_header: true,
            verify_certs: true,
            verify_sign: true,
        }
    }
}

pub fn decrypt<R: io::Read>(
    src_cert: &[u8],
    dst_cert: &[u8],
    dst_key: &[u8],
    params: &DecryptParams,
    file: &mut R,
) -> Result<Vec<u8>, String> {
    let (src_cert, src_key_type, src_cert_key) = load_cert_and_key(src_cert)
        .map_err(|error| format!("Falha no certificado da origem\n{error}"))?;

    let (dst_cert, dst_key_type, dst_cert_key) = load_cert_and_key(dst_cert)
        .map_err(|error| format!("Falha no certificado do destino\n{error}"))?;
    let dst_key =
        load_key(dst_key).map_err(|error| format!("Falha na chave privada do destino\n{error}"))?;
    if params.verify_certs && !dst_key.check_public_key(&dst_cert_key) {
        Err("Chave privada do destino não coresponde ao seu certificado")?;
    }

    let header = header::Header::read_from_file(file)
        .map_err(|error| format!("Falha na leitura do cabelho de segurança\n{error}"))?;
    if params.verify_header {
        header
            .is_valid()
            .map_err(|error| format!("Cabeçalho de segurança inválido\n{error}"))?;
    }
    if params.verify_certs {
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
    file.read_to_end(&mut data)
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
    if params.verify_sign {
        src_cert_key
            .verify(&plain_data, &header.buffer_hash.value())
            .map_err(|error| format!("Assinatura dos dados inválida\n{error}"))?;
    }

    let plain_data: Vec<u8> = match header.special_treatment {
        header::SpecialTreatment::Compress | header::SpecialTreatment::CompressWithoutCrypt
            if params.decompress =>
        {
            Compressors::try_decompress(&plain_data)
                .map_err(|error| format!("Falha na descompactação\n{error}"))?
        }
        _ => plain_data,
    };
    let decoder = match params.decode {
        true => Encoders::default(),
        false => Encoders::Plain,
    };
    let plain_data = match params.decompress {
        true => decoder
            .init()
            .decode(&plain_data)
            .map_err(|error| format!("Falha no decode dos dados\n{error}"))?,
        false => plain_data,
    };

    Ok(plain_data)
}
