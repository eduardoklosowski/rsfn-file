use std::{fmt, io};

pub use self::fields::{
    AsymmetricKeyAlgo, Buffer, CertSerial, ErrorCode, HashAlgo, HeaderLen, PcCert, ProtocolVersion,
    Reserved, SpecialTreatment, SymmetricKeyAlgo,
};

mod fields;

/// Cabeçalho de segurança dos arquivos que trafegam na RSFN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// C01 Tamanho total do Cabeçalho.
    pub len: HeaderLen,
    /// C02 Versão do Protocolo de Segurança.
    pub version: ProtocolVersion,
    /// C03 Código de erro.
    pub error: ErrorCode,
    /// C04 Indicação de tratamento especial.
    pub special_treatment: SpecialTreatment,
    /// C05 Reservado para uso futuro.
    pub reserved: Reserved,
    /// C06 Algoritmo da chave assimétrica do destino.
    pub dst_key_algo: AsymmetricKeyAlgo,
    /// C07 Algoritmo da chave simétrica.
    pub sym_key_algo: SymmetricKeyAlgo,
    /// C08 Algoritmo da chave assimétrica local.
    pub src_key_algo: AsymmetricKeyAlgo,
    /// C09 Algoritmo de "hash".
    pub hash_algo: HashAlgo,
    /// C10 PC do certificado digital do destino.
    pub dst_pc_cert: PcCert,
    /// C11 Série do certificado digital do destino.
    pub dst_cert_serial: CertSerial,
    /// C12 PC do certificado digital da Instituição.
    pub src_pc_cert: PcCert,
    /// C13 Série do certificado digital da Instituição.
    pub src_cert_serial: CertSerial,
    /// C14 Buffer de criptografia da chave simétrica.
    pub buffer_sym_key: Buffer,
    /// C15 Buffer do criptograma de autenticação.
    pub buffer_hash: Buffer,
}

impl Header {
    pub fn read_from_file<R: io::Read>(file: &mut R) -> io::Result<Self> {
        let mut c01 = [0; 2];
        file.read_exact(&mut c01)?;
        let mut c02 = [0; 1];
        file.read_exact(&mut c02)?;
        let mut c03 = [0; 1];
        file.read_exact(&mut c03)?;
        let mut c04 = [0; 1];
        file.read_exact(&mut c04)?;
        let mut c05 = [0; 1];
        file.read_exact(&mut c05)?;
        let mut c06 = [0; 1];
        file.read_exact(&mut c06)?;
        let mut c07 = [0; 1];
        file.read_exact(&mut c07)?;
        let mut c08 = [0; 1];
        file.read_exact(&mut c08)?;
        let mut c09 = [0; 1];
        file.read_exact(&mut c09)?;
        let mut c10 = [0; 1];
        file.read_exact(&mut c10)?;
        let mut c11 = [0; 32];
        file.read_exact(&mut c11)?;
        let mut c12 = [0; 1];
        file.read_exact(&mut c12)?;
        let mut c13 = [0; 32];
        file.read_exact(&mut c13)?;
        let mut c14 = [0; 256];
        file.read_exact(&mut c14)?;
        let mut c15 = [0; 256];
        file.read_exact(&mut c15)?;

        Ok(Self {
            len: c01.into(),
            version: c02.into(),
            error: c03.into(),
            special_treatment: c04.into(),
            reserved: c05.into(),
            dst_key_algo: c06.into(),
            sym_key_algo: c07.into(),
            src_key_algo: c08.into(),
            hash_algo: c09.into(),
            dst_pc_cert: c10.into(),
            dst_cert_serial: c11.into(),
            src_pc_cert: c12.into(),
            src_cert_serial: c13.into(),
            buffer_sym_key: c14.into(),
            buffer_hash: c15.into(),
        })
    }

    pub fn is_header_valid(&self) -> Result<(), String> {
        let errors: Vec<_> = [
            (self.len.is_valid(), "C01 inválido"),
            (self.version.is_valid(), "C02 inválido"),
            (self.error.is_valid(), "C03 inválido"),
            (self.special_treatment.is_valid(), "C04 inválido"),
            (self.reserved.is_valid(), "C05 inválido"),
            (self.dst_key_algo.is_valid(), "C06 inválido"),
            (self.sym_key_algo.is_valid(), "C07 inválido"),
            (self.src_key_algo.is_valid(), "C08 inválido"),
            (self.hash_algo.is_valid(), "C09 inválido"),
            (self.dst_pc_cert.is_valid(), "C10 inválido"),
            (self.dst_cert_serial.is_valid(), "C11 inválido"),
            (self.src_pc_cert.is_valid(), "C12 inválido"),
            (self.src_cert_serial.is_valid(), "C13 inválido"),
            (self.buffer_sym_key.is_valid(), "C14 inválido"),
            (self.buffer_hash.is_valid(), "C15 inválido"),
        ]
        .into_iter()
        .filter_map(|(valid, error)| if valid { None } else { Some(error) })
        .collect();

        match errors.is_empty() {
            true => Ok(()),
            false => Err(errors.join(", ")),
        }
    }

    pub fn write<F: io::Write>(&self, file: &mut F) -> io::Result<()> {
        file.write_all(&self.len.to_bytes())?;
        file.write_all(&self.version.to_bytes())?;
        file.write_all(&self.error.to_bytes())?;
        file.write_all(&self.special_treatment.to_bytes())?;
        file.write_all(&self.reserved.to_bytes())?;
        file.write_all(&self.dst_key_algo.to_bytes())?;
        file.write_all(&self.sym_key_algo.to_bytes())?;
        file.write_all(&self.src_key_algo.to_bytes())?;
        file.write_all(&self.hash_algo.to_bytes())?;
        file.write_all(&self.dst_pc_cert.to_bytes())?;
        file.write_all(&self.dst_cert_serial.to_bytes())?;
        file.write_all(&self.src_pc_cert.to_bytes())?;
        file.write_all(&self.src_cert_serial.to_bytes())?;
        file.write_all(&self.buffer_sym_key.to_bytes())?;
        file.write_all(&self.buffer_hash.to_bytes())?;
        Ok(())
    }
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "================================ BEGIN HEADER ================================"
        )?;
        writeln!(f, "{:45}: {}", "C01 Tamanho do cabeçalho", self.len)?;
        writeln!(f, "{:45}: {}", "C02 Versão do protocolo", self.version)?;
        writeln!(f, "{:45}: {}", "C03 Código de erro", self.error)?;
        writeln!(
            f,
            "{:45}: {}",
            "C04 Tratamento especial", self.special_treatment
        )?;
        writeln!(f, "{:45}: {}", "C05 Reservado", self.reserved)?;
        writeln!(
            f,
            "{:45}: {}",
            "C06 Algoritmo da chave assimétrica do destino", self.dst_key_algo
        )?;
        writeln!(
            f,
            "{:45}: {}",
            "C07 Algoritmo da chave simétrica", self.sym_key_algo
        )?;
        writeln!(
            f,
            "{:45}: {}",
            "C08 Algoritmo da chave assimétrica local", self.src_key_algo
        )?;
        writeln!(f, "{:45}: {}", "C09 Algoritmo de hash", self.hash_algo)?;
        writeln!(
            f,
            "{:45}: {}",
            "C10 PC do certificado do destino", self.dst_pc_cert
        )?;
        writeln!(
            f,
            "{:45}: {}",
            "C11 Série do certificado do destino", self.dst_cert_serial
        )?;
        writeln!(
            f,
            "{:45}: {}",
            "C12 PC do certificado da instituição", self.src_pc_cert
        )?;
        writeln!(
            f,
            "{:45}: {}",
            "C13 Série do certificado da instituição", self.src_cert_serial
        )?;
        writeln!(
            f,
            "{:45}: {}",
            "C14 Buffer da chave simétrica", self.buffer_sym_key
        )?;
        writeln!(
            f,
            "{:45}: {}",
            "C15 Buffer da autenticação da mensagem", self.buffer_hash
        )?;
        write!(
            f,
            "================================ END HEADER ================================"
        )
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn value_plain() {
        let sut = Header {
            len: HeaderLen::Default,
            version: ProtocolVersion::Plain,
            error: ErrorCode::NoError,
            special_treatment: SpecialTreatment::Normal,
            reserved: Reserved::NoValue,
            dst_key_algo: AsymmetricKeyAlgo::Unknown(0),
            sym_key_algo: SymmetricKeyAlgo::Unknown(0),
            src_key_algo: AsymmetricKeyAlgo::Unknown(0),
            hash_algo: HashAlgo::Unknown(0),
            dst_pc_cert: PcCert::Unknown(0),
            dst_cert_serial: [0; 32].into(),
            src_pc_cert: PcCert::Unknown(0),
            src_cert_serial: [0; 32].into(),
            buffer_sym_key: [0; 256].into(),
            buffer_hash: [0; 256].into(),
        };

        assert_eq!(sut.to_string(), "================================ BEGIN HEADER ================================
C01 Tamanho do cabeçalho                     : 0x024c [588]
C02 Versão do protocolo                      : 0x00 [Em claro]
C03 Código de erro                           : 0x00 [Sem erros]
C04 Tratamento especial                      : 0x00 [Uso normal]
C05 Reservado                                : 0x00 [-]
C06 Algoritmo da chave assimétrica do destino: 0x00 [DESCONHECIDO]
C07 Algoritmo da chave simétrica             : 0x00 [DESCONHECIDO]
C08 Algoritmo da chave assimétrica local     : 0x00 [DESCONHECIDO]
C09 Algoritmo de hash                        : 0x00 [DESCONHECIDO]
C10 PC do certificado do destino             : 0x00 [DESCONHECIDO]
C11 Série do certificado do destino          : 0x0000000000000000000000000000000000000000000000000000000000000000 []
C12 PC do certificado da instituição         : 0x00 [DESCONHECIDO]
C13 Série do certificado da instituição      : 0x0000000000000000000000000000000000000000000000000000000000000000 []
C14 Buffer da chave simétrica                : blob [len=0]
C15 Buffer da autenticação da mensagem       : blob [len=0]
================================ END HEADER ================================");
    }

    #[test]
    fn value_version3() {
        let sut = Header {
            len: HeaderLen::Default,
            version: ProtocolVersion::Version3,
            error: ErrorCode::NoError,
            special_treatment: SpecialTreatment::Normal,
            reserved: Reserved::NoValue,
            dst_key_algo: AsymmetricKeyAlgo::RSA2048,
            sym_key_algo: SymmetricKeyAlgo::Aes,
            src_key_algo: AsymmetricKeyAlgo::RSA2048,
            hash_algo: HashAlgo::SHA256,
            dst_pc_cert: PcCert::PessoasFisicas,
            dst_cert_serial: [0; 32].into(),
            src_pc_cert: PcCert::PessoasFisicas,
            src_cert_serial: [0; 32].into(),
            buffer_sym_key: [0; 256].into(),
            buffer_hash: [0; 256].into(),
        };

        assert_eq!(sut.to_string(), "================================ BEGIN HEADER ================================
C01 Tamanho do cabeçalho                     : 0x024c [588]
C02 Versão do protocolo                      : 0x03 [Terceira versão]
C03 Código de erro                           : 0x00 [Sem erros]
C04 Tratamento especial                      : 0x00 [Uso normal]
C05 Reservado                                : 0x00 [-]
C06 Algoritmo da chave assimétrica do destino: 0x02 [RSA com 2048 bits]
C07 Algoritmo da chave simétrica             : 0x02 [AES com 256 bits]
C08 Algoritmo da chave assimétrica local     : 0x02 [RSA com 2048 bits]
C09 Algoritmo de hash                        : 0x03 [SHA-256]
C10 PC do certificado do destino             : 0x03 [Pessoas Físicas]
C11 Série do certificado do destino          : 0x0000000000000000000000000000000000000000000000000000000000000000 []
C12 PC do certificado da instituição         : 0x03 [Pessoas Físicas]
C13 Série do certificado da instituição      : 0x0000000000000000000000000000000000000000000000000000000000000000 []
C14 Buffer da chave simétrica                : blob [len=0]
C15 Buffer da autenticação da mensagem       : blob [len=0]
================================ END HEADER ================================");
    }

    #[test]
    fn value_invalid_len() {
        let sut = Header {
            len: HeaderLen::Unknown(0),
            version: ProtocolVersion::Version3,
            error: ErrorCode::NoError,
            special_treatment: SpecialTreatment::Normal,
            reserved: Reserved::NoValue,
            dst_key_algo: AsymmetricKeyAlgo::RSA2048,
            sym_key_algo: SymmetricKeyAlgo::Aes,
            src_key_algo: AsymmetricKeyAlgo::RSA2048,
            hash_algo: HashAlgo::SHA256,
            dst_pc_cert: PcCert::PessoasFisicas,
            dst_cert_serial: [1; 32].into(),
            src_pc_cert: PcCert::PessoasFisicas,
            src_cert_serial: [1; 32].into(),
            buffer_sym_key: [1; 256].into(),
            buffer_hash: [1; 256].into(),
        };

        assert_eq!(sut.is_header_valid().unwrap_err(), "C01 inválido");
    }

    #[test]
    fn value_invalid_version() {
        let sut = Header {
            len: HeaderLen::Default,
            version: ProtocolVersion::Unknown(1),
            error: ErrorCode::NoError,
            special_treatment: SpecialTreatment::Normal,
            reserved: Reserved::NoValue,
            dst_key_algo: AsymmetricKeyAlgo::RSA2048,
            sym_key_algo: SymmetricKeyAlgo::Aes,
            src_key_algo: AsymmetricKeyAlgo::RSA2048,
            hash_algo: HashAlgo::SHA256,
            dst_pc_cert: PcCert::PessoasFisicas,
            dst_cert_serial: [1; 32].into(),
            src_pc_cert: PcCert::PessoasFisicas,
            src_cert_serial: [1; 32].into(),
            buffer_sym_key: [1; 256].into(),
            buffer_hash: [1; 256].into(),
        };

        assert_eq!(sut.is_header_valid().unwrap_err(), "C02 inválido");
    }

    #[test]
    fn value_invalid_error() {
        let sut = Header {
            len: HeaderLen::Default,
            version: ProtocolVersion::Version3,
            error: ErrorCode::Unknown(1),
            special_treatment: SpecialTreatment::Normal,
            reserved: Reserved::NoValue,
            dst_key_algo: AsymmetricKeyAlgo::RSA2048,
            sym_key_algo: SymmetricKeyAlgo::Aes,
            src_key_algo: AsymmetricKeyAlgo::RSA2048,
            hash_algo: HashAlgo::SHA256,
            dst_pc_cert: PcCert::PessoasFisicas,
            dst_cert_serial: [1; 32].into(),
            src_pc_cert: PcCert::PessoasFisicas,
            src_cert_serial: [1; 32].into(),
            buffer_sym_key: [1; 256].into(),
            buffer_hash: [1; 256].into(),
        };

        assert_eq!(sut.is_header_valid().unwrap_err(), "C03 inválido");
    }

    #[test]
    fn value_invalid_special_treatment() {
        let sut = Header {
            len: HeaderLen::Default,
            version: ProtocolVersion::Version3,
            error: ErrorCode::NoError,
            special_treatment: SpecialTreatment::Unknown(7),
            reserved: Reserved::NoValue,
            dst_key_algo: AsymmetricKeyAlgo::RSA2048,
            sym_key_algo: SymmetricKeyAlgo::Aes,
            src_key_algo: AsymmetricKeyAlgo::RSA2048,
            hash_algo: HashAlgo::SHA256,
            dst_pc_cert: PcCert::PessoasFisicas,
            dst_cert_serial: [1; 32].into(),
            src_pc_cert: PcCert::PessoasFisicas,
            src_cert_serial: [1; 32].into(),
            buffer_sym_key: [1; 256].into(),
            buffer_hash: [1; 256].into(),
        };

        assert_eq!(sut.is_header_valid().unwrap_err(), "C04 inválido");
    }

    #[test]
    fn value_invalid_reserved() {
        let sut = Header {
            len: HeaderLen::Default,
            version: ProtocolVersion::Version3,
            error: ErrorCode::NoError,
            special_treatment: SpecialTreatment::Normal,
            reserved: Reserved::Unknown(1),
            dst_key_algo: AsymmetricKeyAlgo::RSA2048,
            sym_key_algo: SymmetricKeyAlgo::Aes,
            src_key_algo: AsymmetricKeyAlgo::RSA2048,
            hash_algo: HashAlgo::SHA256,
            dst_pc_cert: PcCert::PessoasFisicas,
            dst_cert_serial: [1; 32].into(),
            src_pc_cert: PcCert::PessoasFisicas,
            src_cert_serial: [1; 32].into(),
            buffer_sym_key: [1; 256].into(),
            buffer_hash: [1; 256].into(),
        };

        assert_eq!(sut.is_header_valid().unwrap_err(), "C05 inválido");
    }

    #[test]
    fn value_invalid_dst_key_algo() {
        let sut = Header {
            len: HeaderLen::Default,
            version: ProtocolVersion::Version3,
            error: ErrorCode::NoError,
            special_treatment: SpecialTreatment::Normal,
            reserved: Reserved::NoValue,
            dst_key_algo: AsymmetricKeyAlgo::Unknown(0),
            sym_key_algo: SymmetricKeyAlgo::Aes,
            src_key_algo: AsymmetricKeyAlgo::RSA2048,
            hash_algo: HashAlgo::SHA256,
            dst_pc_cert: PcCert::PessoasFisicas,
            dst_cert_serial: [1; 32].into(),
            src_pc_cert: PcCert::PessoasFisicas,
            src_cert_serial: [1; 32].into(),
            buffer_sym_key: [1; 256].into(),
            buffer_hash: [1; 256].into(),
        };

        assert_eq!(sut.is_header_valid().unwrap_err(), "C06 inválido");
    }

    #[test]
    fn value_invalid_sym_key_algo() {
        let sut = Header {
            len: HeaderLen::Default,
            version: ProtocolVersion::Version3,
            error: ErrorCode::NoError,
            special_treatment: SpecialTreatment::Normal,
            reserved: Reserved::NoValue,
            dst_key_algo: AsymmetricKeyAlgo::RSA2048,
            sym_key_algo: SymmetricKeyAlgo::Unknown(0),
            src_key_algo: AsymmetricKeyAlgo::RSA2048,
            hash_algo: HashAlgo::SHA256,
            dst_pc_cert: PcCert::PessoasFisicas,
            dst_cert_serial: [1; 32].into(),
            src_pc_cert: PcCert::PessoasFisicas,
            src_cert_serial: [1; 32].into(),
            buffer_sym_key: [1; 256].into(),
            buffer_hash: [1; 256].into(),
        };

        assert_eq!(sut.is_header_valid().unwrap_err(), "C07 inválido");
    }

    #[test]
    fn value_invalid_src_key_algo() {
        let sut = Header {
            len: HeaderLen::Default,
            version: ProtocolVersion::Version3,
            error: ErrorCode::NoError,
            special_treatment: SpecialTreatment::Normal,
            reserved: Reserved::NoValue,
            dst_key_algo: AsymmetricKeyAlgo::RSA2048,
            sym_key_algo: SymmetricKeyAlgo::Aes,
            src_key_algo: AsymmetricKeyAlgo::Unknown(0),
            hash_algo: HashAlgo::SHA256,
            dst_pc_cert: PcCert::PessoasFisicas,
            dst_cert_serial: [1; 32].into(),
            src_pc_cert: PcCert::PessoasFisicas,
            src_cert_serial: [1; 32].into(),
            buffer_sym_key: [1; 256].into(),
            buffer_hash: [1; 256].into(),
        };

        assert_eq!(sut.is_header_valid().unwrap_err(), "C08 inválido");
    }

    #[test]
    fn value_invalid_hash_algo() {
        let sut = Header {
            len: HeaderLen::Default,
            version: ProtocolVersion::Version3,
            error: ErrorCode::NoError,
            special_treatment: SpecialTreatment::Normal,
            reserved: Reserved::NoValue,
            dst_key_algo: AsymmetricKeyAlgo::RSA2048,
            sym_key_algo: SymmetricKeyAlgo::Aes,
            src_key_algo: AsymmetricKeyAlgo::RSA2048,
            hash_algo: HashAlgo::Unknown(0),
            dst_pc_cert: PcCert::PessoasFisicas,
            dst_cert_serial: [1; 32].into(),
            src_pc_cert: PcCert::PessoasFisicas,
            src_cert_serial: [1; 32].into(),
            buffer_sym_key: [1; 256].into(),
            buffer_hash: [1; 256].into(),
        };

        assert_eq!(sut.is_header_valid().unwrap_err(), "C09 inválido");
    }

    #[test]
    fn value_invalid_dst_pc_cert() {
        let sut = Header {
            len: HeaderLen::Default,
            version: ProtocolVersion::Version3,
            error: ErrorCode::NoError,
            special_treatment: SpecialTreatment::Normal,
            reserved: Reserved::NoValue,
            dst_key_algo: AsymmetricKeyAlgo::RSA2048,
            sym_key_algo: SymmetricKeyAlgo::Aes,
            src_key_algo: AsymmetricKeyAlgo::RSA2048,
            hash_algo: HashAlgo::SHA256,
            dst_pc_cert: PcCert::Unknown(0),
            dst_cert_serial: [1; 32].into(),
            src_pc_cert: PcCert::PessoasFisicas,
            src_cert_serial: [1; 32].into(),
            buffer_sym_key: [1; 256].into(),
            buffer_hash: [1; 256].into(),
        };

        assert_eq!(sut.is_header_valid().unwrap_err(), "C10 inválido");
    }

    #[test]
    fn value_invalid_dst_cert_serial() {
        let sut = Header {
            len: HeaderLen::Default,
            version: ProtocolVersion::Version3,
            error: ErrorCode::NoError,
            special_treatment: SpecialTreatment::Normal,
            reserved: Reserved::NoValue,
            dst_key_algo: AsymmetricKeyAlgo::RSA2048,
            sym_key_algo: SymmetricKeyAlgo::Aes,
            src_key_algo: AsymmetricKeyAlgo::RSA2048,
            hash_algo: HashAlgo::SHA256,
            dst_pc_cert: PcCert::PessoasFisicas,
            dst_cert_serial: [0; 32].into(),
            src_pc_cert: PcCert::PessoasFisicas,
            src_cert_serial: [1; 32].into(),
            buffer_sym_key: [1; 256].into(),
            buffer_hash: [1; 256].into(),
        };

        assert_eq!(sut.is_header_valid().unwrap_err(), "C11 inválido");
    }

    #[test]
    fn value_invalid_src_pc_cert() {
        let sut = Header {
            len: HeaderLen::Default,
            version: ProtocolVersion::Version3,
            error: ErrorCode::NoError,
            special_treatment: SpecialTreatment::Normal,
            reserved: Reserved::NoValue,
            dst_key_algo: AsymmetricKeyAlgo::RSA2048,
            sym_key_algo: SymmetricKeyAlgo::Aes,
            src_key_algo: AsymmetricKeyAlgo::RSA2048,
            hash_algo: HashAlgo::SHA256,
            dst_pc_cert: PcCert::PessoasFisicas,
            dst_cert_serial: [1; 32].into(),
            src_pc_cert: PcCert::Unknown(0),
            src_cert_serial: [1; 32].into(),
            buffer_sym_key: [1; 256].into(),
            buffer_hash: [1; 256].into(),
        };

        assert_eq!(sut.is_header_valid().unwrap_err(), "C12 inválido");
    }

    #[test]
    fn value_invalid_src_cert_serial() {
        let sut = Header {
            len: HeaderLen::Default,
            version: ProtocolVersion::Version3,
            error: ErrorCode::NoError,
            special_treatment: SpecialTreatment::Normal,
            reserved: Reserved::NoValue,
            dst_key_algo: AsymmetricKeyAlgo::RSA2048,
            sym_key_algo: SymmetricKeyAlgo::Aes,
            src_key_algo: AsymmetricKeyAlgo::RSA2048,
            hash_algo: HashAlgo::SHA256,
            dst_pc_cert: PcCert::PessoasFisicas,
            dst_cert_serial: [1; 32].into(),
            src_pc_cert: PcCert::PessoasFisicas,
            src_cert_serial: [0; 32].into(),
            buffer_sym_key: [1; 256].into(),
            buffer_hash: [1; 256].into(),
        };

        assert_eq!(sut.is_header_valid().unwrap_err(), "C13 inválido");
    }

    #[test]
    fn value_invalid_buffer_sym_key() {
        let sut = Header {
            len: HeaderLen::Default,
            version: ProtocolVersion::Version3,
            error: ErrorCode::NoError,
            special_treatment: SpecialTreatment::Normal,
            reserved: Reserved::NoValue,
            dst_key_algo: AsymmetricKeyAlgo::RSA2048,
            sym_key_algo: SymmetricKeyAlgo::Aes,
            src_key_algo: AsymmetricKeyAlgo::RSA2048,
            hash_algo: HashAlgo::SHA256,
            dst_pc_cert: PcCert::PessoasFisicas,
            dst_cert_serial: [1; 32].into(),
            src_pc_cert: PcCert::PessoasFisicas,
            src_cert_serial: [1; 32].into(),
            buffer_sym_key: [0; 256].into(),
            buffer_hash: [1; 256].into(),
        };

        assert_eq!(sut.is_header_valid().unwrap_err(), "C14 inválido");
    }

    #[test]
    fn value_invalid_buffer_hash() {
        let sut = Header {
            len: HeaderLen::Default,
            version: ProtocolVersion::Version3,
            error: ErrorCode::NoError,
            special_treatment: SpecialTreatment::Normal,
            reserved: Reserved::NoValue,
            dst_key_algo: AsymmetricKeyAlgo::RSA2048,
            sym_key_algo: SymmetricKeyAlgo::Aes,
            src_key_algo: AsymmetricKeyAlgo::RSA2048,
            hash_algo: HashAlgo::SHA256,
            dst_pc_cert: PcCert::PessoasFisicas,
            dst_cert_serial: [1; 32].into(),
            src_pc_cert: PcCert::PessoasFisicas,
            src_cert_serial: [1; 32].into(),
            buffer_sym_key: [1; 256].into(),
            buffer_hash: [0; 256].into(),
        };

        assert_eq!(sut.is_header_valid().unwrap_err(), "C15 inválido");
    }

    #[test]
    fn value_invalid_all_possible_fields() {
        let sut = Header {
            len: HeaderLen::Unknown(0),
            version: ProtocolVersion::Unknown(1),
            error: ErrorCode::Unknown(15),
            special_treatment: SpecialTreatment::Unknown(7),
            reserved: Reserved::Unknown(1),
            dst_key_algo: AsymmetricKeyAlgo::Unknown(0),
            sym_key_algo: SymmetricKeyAlgo::Unknown(0),
            src_key_algo: AsymmetricKeyAlgo::Unknown(0),
            hash_algo: HashAlgo::Unknown(0),
            dst_pc_cert: PcCert::Unknown(0),
            dst_cert_serial: [0; 32].into(),
            src_pc_cert: PcCert::Unknown(0),
            src_cert_serial: [0; 32].into(),
            buffer_sym_key: [0; 256].into(),
            buffer_hash: [0; 256].into(),
        };

        assert_eq!(
            sut.is_header_valid().unwrap_err(),
            (1..=15)
                .map(|i| format!("C{i:02} inválido"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    #[test]
    fn write_read_header_plain() {
        let mut file = Vec::new();

        let a = Header {
            len: HeaderLen::Default,
            version: ProtocolVersion::Plain,
            error: ErrorCode::NoError,
            special_treatment: SpecialTreatment::Normal,
            reserved: Reserved::NoValue,
            dst_key_algo: AsymmetricKeyAlgo::Unknown(0),
            sym_key_algo: SymmetricKeyAlgo::Unknown(0),
            src_key_algo: AsymmetricKeyAlgo::Unknown(0),
            hash_algo: HashAlgo::Unknown(0),
            dst_pc_cert: PcCert::Unknown(0),
            dst_cert_serial: [0; 32].into(),
            src_pc_cert: PcCert::Unknown(0),
            src_cert_serial: [0; 32].into(),
            buffer_sym_key: [0; 256].into(),
            buffer_hash: [0; 256].into(),
        };
        a.write(&mut file).unwrap();

        assert_eq!(file.len(), HeaderLen::Default.value() as usize);

        let mut file = Cursor::new(file);

        let b = Header::read_from_file(&mut file).unwrap();

        assert_eq!(a, b);
    }

    #[test]
    fn write_read_header_version3() {
        let mut file = Vec::new();

        let a = Header {
            len: HeaderLen::Default,
            version: ProtocolVersion::Version3,
            error: ErrorCode::NoError,
            special_treatment: SpecialTreatment::Normal,
            reserved: Reserved::NoValue,
            dst_key_algo: AsymmetricKeyAlgo::RSA2048,
            sym_key_algo: SymmetricKeyAlgo::Aes,
            src_key_algo: AsymmetricKeyAlgo::RSA2048,
            hash_algo: HashAlgo::SHA256,
            dst_pc_cert: PcCert::PessoasFisicas,
            dst_cert_serial: [0; 32].into(),
            src_pc_cert: PcCert::PessoasFisicas,
            src_cert_serial: [0; 32].into(),
            buffer_sym_key: [0; 256].into(),
            buffer_hash: [0; 256].into(),
        };
        a.write(&mut file).unwrap();

        assert_eq!(file.len(), HeaderLen::Default.value() as usize);

        let mut file = Cursor::new(file);

        let b = Header::read_from_file(&mut file).unwrap();

        assert_eq!(a, b);
    }
}
