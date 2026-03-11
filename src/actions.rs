use std::{fmt, io};

use crate::{
    cert::load_cert_and_key,
    ciphers::{Aes256, load_key},
    compress::Compressors,
    encode::Encoders,
    header,
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum CertError {
    MismatchSourceCert,
    MismatchSourceIssuer,
    MismatchSourceKeyAlgo,
    MismatchSourceCertAndKey,
    MismatchDestinationCert,
    MismatchDestinationIssuer,
    MismatchDestinationKeyAlgo,
    MismatchDestinationCertAndKey,
}

impl fmt::Display for CertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::MismatchSourceCert => "Certificado da origem não coincide",
                Self::MismatchSourceIssuer => "Emissor do certificado da origem não coincide",
                Self::MismatchSourceKeyAlgo =>
                    "Tipo da chave do certificado da origem não coincide",
                Self::MismatchSourceCertAndKey =>
                    "Chave privada da origem não coresponde ao seu certificado",
                Self::MismatchDestinationCert => "Certificado do destino não coincide",
                Self::MismatchDestinationIssuer => "Emissor do certificado do destino não coincide",
                Self::MismatchDestinationKeyAlgo =>
                    "Tipo da chave do certificado do destino não coincide",
                Self::MismatchDestinationCertAndKey =>
                    "Chave privada do destino não coresponde ao seu certificado",
            }
        )
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum CryptError {
    Plain,
    DecryptSymmetricKey { error: String },
    DecryptContent { error: String },
}

impl CryptError {
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Plain)
    }
}

impl fmt::Display for CryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Plain => "Conteúdo em claro".to_string(),
                Self::DecryptSymmetricKey { error } =>
                    format!("Falha ao descriptografar chave simétrica\n{error}"),
                Self::DecryptContent { error } =>
                    format!("Falha ao descriptografar os dados\n{error}"),
            }
        )
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SignatureError {
    Blank,
    Invalid { error: String },
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Blank => "Assinatura em branco".to_string(),
                Self::Invalid { error } => format!("Assinatura dos dados inválida\n{error}"),
            }
        )
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ProcessContentError {
    Compress { error: String },
    Decompress { error: String },
    Encode { error: String },
    Decode { error: String },
}

impl fmt::Display for ProcessContentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Compress { error } => format!("Falha na compactação do arquivo\n{error}"),
                Self::Decompress { error } => format!("Falha na descompactação\n{error}"),
                Self::Encode { error } => format!("Falha no encode dos dados UTF-8\n{error}"),
                Self::Decode { error } => format!("Falha no decode dos dados\n{error}"),
            }
        )
    }
}

// Header

pub fn load_header<R: io::Read>(file: &mut R) -> Result<header::Header, String> {
    header::Header::read_from_file(file)
        .map_err(|error| format!("Falha na leitura do cabeçalho de segurança\n{error}"))
}

// Encrypt

#[derive(Debug)]
pub struct EncryptResult {
    header: header::Header,
    cert_error: Option<CertError>,
    data: Vec<u8>,
}

impl EncryptResult {
    pub fn new(header: header::Header, cert_error: Option<CertError>, data: Vec<u8>) -> Self {
        Self {
            header,
            cert_error,
            data,
        }
    }

    pub fn header(&self) -> &header::Header {
        &self.header
    }

    pub fn is_valid_cert(&self) -> Result<(), CertError> {
        match &self.cert_error {
            None => Ok(()),
            Some(error) => Err(error.clone()),
        }
    }

    pub fn data(&self) -> &Vec<u8> {
        &self.data
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum EncryptError {
    SourceCert {
        error: String,
    },
    SourceKey {
        error: String,
    },
    DestinationCert {
        error: String,
    },
    ReadContent {
        error: String,
        cert_error: Option<CertError>,
    },
    Encode {
        error: String,
        cert_error: Option<CertError>,
    },
    Compress {
        error: String,
        cert_error: Option<CertError>,
    },
    EncryptContent {
        error: String,
        cert_error: Option<CertError>,
    },
    EncryptSymmetricKey {
        error: String,
        cert_error: Option<CertError>,
    },
    FormatHeader {
        error: String,
        cert_error: Option<CertError>,
    },
}

impl fmt::Display for EncryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::SourceCert { error } => format!("Falha no certificado da origem\n{error}"),
                Self::SourceKey { error } => format!("Falha na chave privada da origem\n{error}"),
                Self::DestinationCert { error } =>
                    format!("Falha no certificado do destino\n{error}"),
                Self::ReadContent { error, .. } =>
                    format!("Falha ao ler dados a serem criptografados\n{error}"),
                Self::Encode { error, .. } => format!("Falha no encode dos dados UTF-8\n{error}"),
                Self::Compress { error, .. } => format!("Falha na compactação do arquivo\n{error}"),
                Self::EncryptContent { error, .. } =>
                    format!("Falha na criptografia do arquivo\n{error}"),
                Self::EncryptSymmetricKey { error, .. } =>
                    format!("Falha na criptografia da chave simétrica\n{error}"),
                Self::FormatHeader { error, .. } =>
                    format!("Erro ao formatar o cabeçalho de segurança\n{error}"),
            }
        )
    }
}

#[derive(Debug)]
pub struct Encrypter {
    special_treatment: Option<header::SpecialTreatment>,
    crypt: bool,
    compressor: Compressors,
    encoder: Encoders,
}

impl Default for Encrypter {
    fn default() -> Self {
        Self::new()
    }
}

impl Encrypter {
    pub fn new() -> Self {
        Self {
            special_treatment: None,
            crypt: true,
            compressor: Compressors::default(),
            encoder: Encoders::default(),
        }
    }

    pub fn set_special_treatment(&mut self, value: Option<header::SpecialTreatment>) {
        self.special_treatment = value;
    }

    pub fn set_crypt(&mut self, value: bool) {
        self.crypt = value;
    }

    pub fn set_compressor(&mut self, value: Compressors) {
        self.compressor = value;
    }

    pub fn set_encoder(&mut self, value: Encoders) {
        self.encoder = value;
    }

    pub fn encrypt<R: io::Read>(
        &self,
        src_cert: &[u8],
        src_key: &[u8],
        dst_cert: &[u8],
        file: &mut R,
    ) -> Result<EncryptResult, EncryptError> {
        let (src_cert, src_cert_key_type, src_cert_key) =
            load_cert_and_key(src_cert).map_err(|error| EncryptError::SourceCert { error })?;
        let src_key = load_key(src_key).map_err(|error| EncryptError::SourceKey { error })?;

        let (dst_cert, dst_cert_key_type, dst_cert_key) =
            load_cert_and_key(dst_cert).map_err(|error| EncryptError::DestinationCert { error })?;

        let cert_error = if !src_key.check_public_key(&src_cert_key) {
            Some(CertError::MismatchSourceCertAndKey)
        } else {
            None
        };

        let mut data = Vec::new();
        file.read_to_end(&mut data)
            .map_err(|error| EncryptError::ReadContent {
                error: error.to_string(),
                cert_error: cert_error.clone(),
            })?;
        let data = self
            .encoder
            .init()
            .encode(&data)
            .map_err(|error| EncryptError::Encode {
                error,
                cert_error: cert_error.clone(),
            })?;
        let data =
            self.compressor
                .init()
                .compress(&data)
                .map_err(|error| EncryptError::Compress {
                    error,
                    cert_error: cert_error.clone(),
                })?;

        let (cipher_sym_key, cipher_data) = if self.crypt {
            let aes = Aes256::generate_new_key();
            let cipher_data = aes
                .encrypt(&data)
                .map_err(|error| EncryptError::EncryptContent {
                    error,
                    cert_error: cert_error.clone(),
                })?;
            let cipher_sym_key = dst_cert_key.encrypt(&aes.export_key()).map_err(|error| {
                EncryptError::EncryptSymmetricKey {
                    error,
                    cert_error: cert_error.clone(),
                }
            })?;
            (cipher_sym_key, cipher_data)
        } else {
            ([0; 256].into(), data.clone())
        };
        let sign = src_key.sign(&data);

        let special_treatment = match &self.special_treatment {
            Some(value) => value.clone(),
            None => match self.compressor {
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
            dst_key_algo: dst_cert_key_type,
            sym_key_algo: header::SymmetricKeyAlgo::Aes,
            src_key_algo: src_cert_key_type,
            hash_algo: header::HashAlgo::SHA256,
            dst_pc_cert: dst_cert.issuer(),
            dst_cert_serial: dst_cert.serial(),
            src_pc_cert: src_cert.issuer(),
            src_cert_serial: src_cert.serial(),
            buffer_sym_key: cipher_sym_key
                .try_into()
                .map_err(|_| EncryptError::FormatHeader {
                    error: "Tamanho da chave simétrica incorreto".to_string(),
                    cert_error: cert_error.clone(),
                })?,
            buffer_hash: sign.try_into().map_err(|_| EncryptError::FormatHeader {
                error: "Tamanho da assinatura incorreto".to_string(),
                cert_error: cert_error.clone(),
            })?,
        };

        let mut output = header.to_bytes();
        output.extend(cipher_data);
        Ok(EncryptResult {
            header,
            cert_error,
            data: output,
        })
    }
}

// Decrypt

#[derive(Debug)]
pub struct DecryptResult {
    header: header::Header,
    cert_error: Option<CertError>,
    signature_error: Option<SignatureError>,
    data: Vec<u8>,
}

impl DecryptResult {
    pub fn new(
        header: header::Header,
        cert_error: Option<CertError>,
        signature_error: Option<SignatureError>,
        data: Vec<u8>,
    ) -> Self {
        Self {
            header,
            cert_error,
            signature_error,
            data,
        }
    }

    pub fn header(&self) -> &header::Header {
        &self.header
    }

    pub fn is_encrypted_content(&self) -> bool {
        self.header.is_encrypted_content()
    }

    pub fn is_compressed_content(&self) -> bool {
        self.header.is_compressed_content()
    }

    pub fn is_valid_cert(&self) -> Result<(), CertError> {
        match &self.cert_error {
            None => Ok(()),
            Some(error) => Err(error.clone()),
        }
    }

    pub fn is_valid_signature(&self) -> Result<(), SignatureError> {
        match &self.signature_error {
            None => Ok(()),
            Some(error) => Err(error.clone()),
        }
    }

    pub fn data(&self) -> &Vec<u8> {
        &self.data
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum DecryptError {
    SourceCert {
        error: String,
    },
    DestinationCert {
        error: String,
    },
    DestinationKey {
        error: String,
    },
    ReadHeader {
        error: String,
    },
    ReadContent {
        error: String,
        header: header::Header,
        cert_error: Option<CertError>,
    },
    DecryptSymmetricKey {
        error: String,
        header: header::Header,
        cert_error: Option<CertError>,
    },
    DecryptContent {
        error: String,
        header: header::Header,
        cert_error: Option<CertError>,
    },
    Decompress {
        error: String,
        header: header::Header,
        cert_error: Option<CertError>,
        signature_error: Option<SignatureError>,
        data: Vec<u8>,
    },
    Decode {
        error: String,
        header: header::Header,
        cert_error: Option<CertError>,
        signature_error: Option<SignatureError>,
        data: Vec<u8>,
    },
}

impl fmt::Display for DecryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::SourceCert { error } => format!("Falha no certificado da origem\n{error}"),
                Self::DestinationCert { error } =>
                    format!("Falha no certificado do destino\n{error}"),
                Self::DestinationKey { error } =>
                    format!("Falha na chave privada do destino\n{error}"),
                Self::ReadHeader { error } =>
                    format!("Falha na leitura do cabelho de segurança\n{error}"),
                Self::ReadContent { error, .. } =>
                    format!("Falha ao ler dados a serem descriptografados\n{error}"),
                Self::DecryptSymmetricKey { error, .. } =>
                    format!("Falha ao descriptografar chave simétrica\n{error}"),
                Self::DecryptContent { error, .. } =>
                    format!("Falha ao descriptografar os dados\n{error}"),
                Self::Decompress { error, .. } => format!("Falha na descompactação\n{error}"),
                Self::Decode { error, .. } => format!("Falha no decode dos dados\n{error}"),
            }
        )
    }
}

#[derive(Debug)]
pub struct Decrypter {
    decompress: bool,
    decode: bool,
}

impl Default for Decrypter {
    fn default() -> Self {
        Self::new()
    }
}

impl Decrypter {
    pub fn new() -> Self {
        Self {
            decompress: true,
            decode: true,
        }
    }

    pub fn set_decompress(&mut self, value: bool) {
        self.decompress = value;
    }

    pub fn set_decode(&mut self, value: bool) {
        self.decode = value;
    }

    #[allow(clippy::result_large_err)]
    pub fn decrypt<R: io::Read>(
        &self,
        src_cert: &[u8],
        dst_cert: &[u8],
        dst_key: &[u8],
        file: &mut R,
    ) -> Result<DecryptResult, DecryptError> {
        let (src_cert, src_cert_key_type, src_cert_key) =
            load_cert_and_key(src_cert).map_err(|error| DecryptError::SourceCert { error })?;

        let (dst_cert, dst_cert_key_type, dst_cert_key) =
            load_cert_and_key(dst_cert).map_err(|error| DecryptError::DestinationCert { error })?;
        let dst_key = load_key(dst_key).map_err(|error| DecryptError::DestinationKey { error })?;

        let header =
            header::Header::read_from_file(file).map_err(|error| DecryptError::ReadHeader {
                error: error.to_string(),
            })?;

        let cert_error = if !dst_key.check_public_key(&dst_cert_key) {
            Some(CertError::MismatchDestinationCertAndKey)
        } else if header.src_cert_serial != src_cert.serial() {
            Some(CertError::MismatchSourceCert)
        } else if header.src_pc_cert != src_cert.issuer() {
            Some(CertError::MismatchSourceIssuer)
        } else if header.src_key_algo != src_cert_key_type {
            Some(CertError::MismatchSourceKeyAlgo)
        } else if header.dst_cert_serial != dst_cert.serial() {
            Some(CertError::MismatchDestinationCert)
        } else if header.dst_pc_cert != dst_cert.issuer() {
            Some(CertError::MismatchDestinationIssuer)
        } else if header.dst_key_algo != dst_cert_key_type {
            Some(CertError::MismatchDestinationKeyAlgo)
        } else {
            None
        };

        let mut data = Vec::new();
        file.read_to_end(&mut data)
            .map_err(|error| DecryptError::ReadContent {
                error: error.to_string(),
                header: header.clone(),
                cert_error: cert_error.clone(),
            })?;

        let plain_data = if header.is_encrypted_content() {
            let sym_key = dst_key
                .decrypt(&header.buffer_sym_key.value())
                .map_err(|error| DecryptError::DecryptSymmetricKey {
                    error,
                    header: header.clone(),
                    cert_error: cert_error.clone(),
                })?;
            let aes = Aes256::new(&sym_key);
            aes.decrypt(&data)
                .map_err(|error| DecryptError::DecryptContent {
                    error,
                    header: header.clone(),
                    cert_error: cert_error.clone(),
                })?
        } else {
            data
        };

        let signature_error = src_cert_key
            .verify(&plain_data, &header.buffer_hash.value())
            .map_err(|error| SignatureError::Invalid { error })
            .err();

        let plain_data = if header.is_compressed_content() && self.decompress {
            Compressors::try_decompress(&plain_data).map_err(|error| DecryptError::Decompress {
                error,
                header: header.clone(),
                cert_error: cert_error.clone(),
                signature_error: signature_error.clone(),
                data: plain_data,
            })?
        } else {
            plain_data
        };
        let plain_data = {
            let decoder = match self.decode {
                true => Encoders::default(),
                false => Encoders::Plain,
            };
            decoder
                .init()
                .decode(&plain_data)
                .map_err(|error| DecryptError::Decode {
                    error,
                    header: header.clone(),
                    cert_error: cert_error.clone(),
                    signature_error: signature_error.clone(),
                    data: plain_data,
                })?
        };

        Ok(DecryptResult {
            header,
            cert_error,
            signature_error,
            data: plain_data,
        })
    }
}
