use std::fmt;

/// Código de erro.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorCode {
    NoError,
    InvalidHeaderLen,
    InvalidVersion,
    InvalidDstKeyAlgo,
    InvalidSymmetricAlgo,
    InvalidSrcKeyAlgo,
    InvalidHashAlgo,
    InvalidDstPC,
    InvalidDstSerial,
    InvalidSrcPC,
    InvalidSrcSerial,
    InvalidSign,
    IncorrectSrcCert,
    ErrorOnExtractSymmetricKey,
    ErrorOnSymmetricAlgo,
    InvalidMsgLen,
    DisabledCert,
    OverdueOrRevokedCert,
    ErrorOnSoftware,
    InvalidSpecificUse,
    NotEnabledCert,
    NotSecurityError,
    Unknown(u8),
}

impl From<[u8; 1]> for ErrorCode {
    fn from(value: [u8; 1]) -> Self {
        value[0].into()
    }
}

impl From<u8> for ErrorCode {
    fn from(value: u8) -> Self {
        match value {
            0x00 => Self::NoError,
            0x01 => Self::InvalidHeaderLen,
            0x02 => Self::InvalidVersion,
            0x03 => Self::InvalidDstKeyAlgo,
            0x04 => Self::InvalidSymmetricAlgo,
            0x05 => Self::InvalidSrcKeyAlgo,
            0x06 => Self::InvalidHashAlgo,
            0x07 => Self::InvalidDstPC,
            0x08 => Self::InvalidDstSerial,
            0x09 => Self::InvalidSrcPC,
            0x0a => Self::InvalidSrcSerial,
            0x0b => Self::InvalidSign,
            0x0c => Self::IncorrectSrcCert,
            0x0d => Self::ErrorOnExtractSymmetricKey,
            0x0e => Self::ErrorOnSymmetricAlgo,
            0x0f => Self::InvalidMsgLen,
            0x10 => Self::DisabledCert,
            0x11 => Self::OverdueOrRevokedCert,
            0x12 => Self::ErrorOnSoftware,
            0x13 => Self::InvalidSpecificUse,
            0x14 => Self::NotEnabledCert,
            0xff => Self::NotSecurityError,
            n => Self::Unknown(n),
        }
    }
}

impl ErrorCode {
    pub fn value(&self) -> u8 {
        match self {
            Self::NoError => 0x00,
            Self::InvalidHeaderLen => 0x01,
            Self::InvalidVersion => 0x02,
            Self::InvalidDstKeyAlgo => 0x03,
            Self::InvalidSymmetricAlgo => 0x04,
            Self::InvalidSrcKeyAlgo => 0x05,
            Self::InvalidHashAlgo => 0x06,
            Self::InvalidDstPC => 0x07,
            Self::InvalidDstSerial => 0x08,
            Self::InvalidSrcPC => 0x09,
            Self::InvalidSrcSerial => 0x0a,
            Self::InvalidSign => 0x0b,
            Self::IncorrectSrcCert => 0x0c,
            Self::ErrorOnExtractSymmetricKey => 0x0d,
            Self::ErrorOnSymmetricAlgo => 0x0e,
            Self::InvalidMsgLen => 0x0f,
            Self::DisabledCert => 0x10,
            Self::OverdueOrRevokedCert => 0x11,
            Self::ErrorOnSoftware => 0x12,
            Self::InvalidSpecificUse => 0x13,
            Self::NotEnabledCert => 0x14,
            Self::NotSecurityError => 0xff,
            Self::Unknown(n) => *n,
        }
    }

    pub fn describe_value(&self) -> String {
        match self {
            Self::NoError => "Sem erros".to_string(),
            Self::InvalidHeaderLen => "Tamanho do cabeçalho de segurança zerado ou incompatível com os possíveis".to_string(),
            Self::InvalidVersion => "Versão inválida ou incompatível com o tamanho e/ou conexão".to_string(),
            Self::InvalidDstKeyAlgo => "Algoritmo da chave do destinatário inválido ou divergente do certificado".to_string(),
            Self::InvalidSymmetricAlgo => "Algoritmo simétrico inválido".to_string(),
            Self::InvalidSrcKeyAlgo => "Algoritmo da chave do certificado digital da Instituição inválido ou divergente do certificado".to_string(),
            Self::InvalidHashAlgo => "Algoritmo de \"hash\" não corresponde ao indicado ou é inválido".to_string(),
            Self::InvalidDstPC => "Código da PC do certificado do destinatário inválido".to_string(),
            Self::InvalidDstSerial => "Número de série do certificado do destinatário inválido (não foi emitido pela AC)".to_string(),
            Self::InvalidSrcPC => "Código da PC do certificado inválido".to_string(),
            Self::InvalidSrcSerial => "Número de série do certificado digital da Instituição inválido (não foi emitido pela AC)".to_string(),
            Self::InvalidSign => "Criptograma de autenticação da Mensagem inválido ou com erro".to_string(),
            Self::IncorrectSrcCert => "Certificado não é do emissor da mensagem (titular da fila no MQ)".to_string(),
            Self::ErrorOnExtractSymmetricKey => "Erro na extração da chave simétrica".to_string(),
            Self::ErrorOnSymmetricAlgo => "Erro gerado pelo algoritmo simétrico".to_string(),
            Self::InvalidMsgLen => "Tamanho da mensagem não múltiplo de 8 bytes (específico para a segunda versão do Protocolo de Segurança)".to_string(),
            Self::DisabledCert => "Certificado usado não está ativado".to_string(),
            Self::OverdueOrRevokedCert => "Certificado usado está vencido ou revogado pela Instituição".to_string(),
            Self::ErrorOnSoftware => "Erro genérico de software da camada de segurança".to_string(),
            Self::InvalidSpecificUse => "Indicação de uso específico inválida ou incompatível".to_string(),
            Self::NotEnabledCert => "Certificado inválido (Usar certificado \"a ativar\" na GEN0006)".to_string(),
            Self::NotSecurityError => "Erro fora do escopo de segurança".to_string(),
            Self::Unknown(_) => "DESCONHECIDO".to_string(),
        }
    }

    pub fn is_valid(&self) -> bool {
        !matches!(self, Self::Unknown(_))
    }

    pub fn to_bytes(&self) -> [u8; 1] {
        [self.value()]
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = self.value();
        let desc = self.describe_value();
        write!(f, "0x{value:02x} [{desc}]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_no_error() {
        let sut: ErrorCode = [0x00].into();

        assert_eq!(sut, ErrorCode::NoError);
        assert_eq!(sut, 0x00.into());
        assert_eq!(sut.value(), 0x00);
        assert_eq!(sut.describe_value(), "Sem erros");
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x00]);
        assert_eq!(sut.to_string(), "0x00 [Sem erros]");
    }

    #[test]
    fn value_invalid_header_len() {
        let sut: ErrorCode = [0x01].into();

        assert_eq!(sut, ErrorCode::InvalidHeaderLen);
        assert_eq!(sut, 0x01.into());
        assert_eq!(sut.value(), 0x01);
        assert_eq!(
            sut.describe_value(),
            "Tamanho do cabeçalho de segurança zerado ou incompatível com os possíveis"
        );
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x01]);
        assert_eq!(
            sut.to_string(),
            "0x01 [Tamanho do cabeçalho de segurança zerado ou incompatível com os possíveis]"
        );
    }

    #[test]
    fn value_invalid_version() {
        let sut: ErrorCode = [0x02].into();

        assert_eq!(sut, ErrorCode::InvalidVersion);
        assert_eq!(sut, 0x02.into());
        assert_eq!(sut.value(), 0x02);
        assert_eq!(
            sut.describe_value(),
            "Versão inválida ou incompatível com o tamanho e/ou conexão"
        );
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x02]);
        assert_eq!(
            sut.to_string(),
            "0x02 [Versão inválida ou incompatível com o tamanho e/ou conexão]"
        );
    }

    #[test]
    fn value_invalid_dst_key_algo() {
        let sut: ErrorCode = [0x03].into();

        assert_eq!(sut, ErrorCode::InvalidDstKeyAlgo);
        assert_eq!(sut, 0x03.into());
        assert_eq!(sut.value(), 0x03);
        assert_eq!(
            sut.describe_value(),
            "Algoritmo da chave do destinatário inválido ou divergente do certificado"
        );
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x03]);
        assert_eq!(
            sut.to_string(),
            "0x03 [Algoritmo da chave do destinatário inválido ou divergente do certificado]"
        );
    }

    #[test]
    fn value_invalid_symmetric_algo() {
        let sut: ErrorCode = [0x04].into();

        assert_eq!(sut, ErrorCode::InvalidSymmetricAlgo);
        assert_eq!(sut, 0x04.into());
        assert_eq!(sut.value(), 0x04);
        assert_eq!(sut.describe_value(), "Algoritmo simétrico inválido");
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x04]);
        assert_eq!(sut.to_string(), "0x04 [Algoritmo simétrico inválido]");
    }

    #[test]
    fn value_invalid_src_key_algo() {
        let sut: ErrorCode = [0x05].into();

        assert_eq!(sut, ErrorCode::InvalidSrcKeyAlgo);
        assert_eq!(sut, 0x05.into());
        assert_eq!(sut.value(), 0x05);
        assert_eq!(
            sut.describe_value(),
            "Algoritmo da chave do certificado digital da Instituição inválido ou divergente do certificado"
        );
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x05]);
        assert_eq!(
            sut.to_string(),
            "0x05 [Algoritmo da chave do certificado digital da Instituição inválido ou divergente do certificado]"
        );
    }

    #[test]
    fn value_invalid_hash_algo() {
        let sut: ErrorCode = [0x06].into();

        assert_eq!(sut, ErrorCode::InvalidHashAlgo);
        assert_eq!(sut, 0x06.into());
        assert_eq!(sut.value(), 0x06);
        assert_eq!(
            sut.describe_value(),
            "Algoritmo de \"hash\" não corresponde ao indicado ou é inválido"
        );
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x06]);
        assert_eq!(
            sut.to_string(),
            "0x06 [Algoritmo de \"hash\" não corresponde ao indicado ou é inválido]"
        );
    }

    #[test]
    fn value_invalid_dst_pc() {
        let sut: ErrorCode = [0x07].into();

        assert_eq!(sut, ErrorCode::InvalidDstPC);
        assert_eq!(sut, 0x07.into());
        assert_eq!(sut.value(), 0x07);
        assert_eq!(
            sut.describe_value(),
            "Código da PC do certificado do destinatário inválido"
        );
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x07]);
        assert_eq!(
            sut.to_string(),
            "0x07 [Código da PC do certificado do destinatário inválido]"
        );
    }

    #[test]
    fn value_invalid_dst_serial() {
        let sut: ErrorCode = [0x08].into();

        assert_eq!(sut, ErrorCode::InvalidDstSerial);
        assert_eq!(sut, 0x08.into());
        assert_eq!(sut.value(), 0x08);
        assert_eq!(
            sut.describe_value(),
            "Número de série do certificado do destinatário inválido (não foi emitido pela AC)"
        );
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x08]);
        assert_eq!(
            sut.to_string(),
            "0x08 [Número de série do certificado do destinatário inválido (não foi emitido pela AC)]"
        );
    }

    #[test]
    fn value_invalid_src_pc() {
        let sut: ErrorCode = [0x09].into();

        assert_eq!(sut, ErrorCode::InvalidSrcPC);
        assert_eq!(sut, 0x09.into());
        assert_eq!(sut.value(), 0x09);
        assert_eq!(sut.describe_value(), "Código da PC do certificado inválido");
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x09]);
        assert_eq!(
            sut.to_string(),
            "0x09 [Código da PC do certificado inválido]"
        );
    }

    #[test]
    fn value_invalid_src_serial() {
        let sut: ErrorCode = [0x0a].into();

        assert_eq!(sut, ErrorCode::InvalidSrcSerial);
        assert_eq!(sut, 0x0a.into());
        assert_eq!(sut.value(), 0x0a);
        assert_eq!(
            sut.describe_value(),
            "Número de série do certificado digital da Instituição inválido (não foi emitido pela AC)"
        );
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x0a]);
        assert_eq!(
            sut.to_string(),
            "0x0a [Número de série do certificado digital da Instituição inválido (não foi emitido pela AC)]"
        );
    }

    #[test]
    fn value_invalid_sign() {
        let sut: ErrorCode = [0x0b].into();

        assert_eq!(sut, ErrorCode::InvalidSign);
        assert_eq!(sut, 0x0b.into());
        assert_eq!(sut.value(), 0x0b);
        assert_eq!(
            sut.describe_value(),
            "Criptograma de autenticação da Mensagem inválido ou com erro"
        );
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x0b]);
        assert_eq!(
            sut.to_string(),
            "0x0b [Criptograma de autenticação da Mensagem inválido ou com erro]"
        );
    }

    #[test]
    fn value_incorrect_src_cert() {
        let sut: ErrorCode = [0x0c].into();

        assert_eq!(sut, ErrorCode::IncorrectSrcCert);
        assert_eq!(sut, 0x0c.into());
        assert_eq!(sut.value(), 0x0c);
        assert_eq!(
            sut.describe_value(),
            "Certificado não é do emissor da mensagem (titular da fila no MQ)"
        );
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x0c]);
        assert_eq!(
            sut.to_string(),
            "0x0c [Certificado não é do emissor da mensagem (titular da fila no MQ)]"
        );
    }

    #[test]
    fn value_error_on_extract_symmetric_key() {
        let sut: ErrorCode = [0x0d].into();

        assert_eq!(sut, ErrorCode::ErrorOnExtractSymmetricKey);
        assert_eq!(sut, 0x0d.into());
        assert_eq!(sut.value(), 0x0d);
        assert_eq!(sut.describe_value(), "Erro na extração da chave simétrica");
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x0d]);
        assert_eq!(
            sut.to_string(),
            "0x0d [Erro na extração da chave simétrica]"
        );
    }

    #[test]
    fn value_error_on_symmetric_algo() {
        let sut: ErrorCode = [0x0e].into();

        assert_eq!(sut, ErrorCode::ErrorOnSymmetricAlgo);
        assert_eq!(sut, 0x0e.into());
        assert_eq!(sut.value(), 0x0e);
        assert_eq!(sut.describe_value(), "Erro gerado pelo algoritmo simétrico");
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x0e]);
        assert_eq!(
            sut.to_string(),
            "0x0e [Erro gerado pelo algoritmo simétrico]"
        );
    }

    #[test]
    fn value_invalid_msg_len() {
        let sut: ErrorCode = [0x0f].into();

        assert_eq!(sut, ErrorCode::InvalidMsgLen);
        assert_eq!(sut, 0x0f.into());
        assert_eq!(sut.value(), 0x0f);
        assert_eq!(
            sut.describe_value(),
            "Tamanho da mensagem não múltiplo de 8 bytes (específico para a segunda versão do Protocolo de Segurança)"
        );
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x0f]);
        assert_eq!(
            sut.to_string(),
            "0x0f [Tamanho da mensagem não múltiplo de 8 bytes (específico para a segunda versão do Protocolo de Segurança)]"
        );
    }

    #[test]
    fn value_disabled_cert() {
        let sut: ErrorCode = [0x10].into();

        assert_eq!(sut, ErrorCode::DisabledCert);
        assert_eq!(sut, 0x10.into());
        assert_eq!(sut.value(), 0x10);
        assert_eq!(sut.describe_value(), "Certificado usado não está ativado");
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x10]);
        assert_eq!(sut.to_string(), "0x10 [Certificado usado não está ativado]");
    }

    #[test]
    fn value_overdue_or_revoked_cert() {
        let sut: ErrorCode = [0x11].into();

        assert_eq!(sut, ErrorCode::OverdueOrRevokedCert);
        assert_eq!(sut, 0x11.into());
        assert_eq!(sut.value(), 0x11);
        assert_eq!(
            sut.describe_value(),
            "Certificado usado está vencido ou revogado pela Instituição"
        );
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x11]);
        assert_eq!(
            sut.to_string(),
            "0x11 [Certificado usado está vencido ou revogado pela Instituição]"
        );
    }

    #[test]
    fn value_error_on_software() {
        let sut: ErrorCode = [0x12].into();

        assert_eq!(sut, ErrorCode::ErrorOnSoftware);
        assert_eq!(sut, 0x12.into());
        assert_eq!(sut.value(), 0x12);
        assert_eq!(
            sut.describe_value(),
            "Erro genérico de software da camada de segurança"
        );
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x12]);
        assert_eq!(
            sut.to_string(),
            "0x12 [Erro genérico de software da camada de segurança]"
        );
    }

    #[test]
    fn value_invalid_specific_use() {
        let sut: ErrorCode = [0x13].into();

        assert_eq!(sut, ErrorCode::InvalidSpecificUse);
        assert_eq!(sut, 0x13.into());
        assert_eq!(sut.value(), 0x13);
        assert_eq!(
            sut.describe_value(),
            "Indicação de uso específico inválida ou incompatível"
        );
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x13]);
        assert_eq!(
            sut.to_string(),
            "0x13 [Indicação de uso específico inválida ou incompatível]"
        );
    }

    #[test]
    fn value_not_enabled_cert() {
        let sut: ErrorCode = [0x14].into();

        assert_eq!(sut, ErrorCode::NotEnabledCert);
        assert_eq!(sut, 0x14.into());
        assert_eq!(sut.value(), 0x14);
        assert_eq!(
            sut.describe_value(),
            "Certificado inválido (Usar certificado \"a ativar\" na GEN0006)"
        );
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x14]);
        assert_eq!(
            sut.to_string(),
            "0x14 [Certificado inválido (Usar certificado \"a ativar\" na GEN0006)]"
        );
    }

    #[test]
    fn value_not_security_error() {
        let sut: ErrorCode = [0xff].into();

        assert_eq!(sut, ErrorCode::NotSecurityError);
        assert_eq!(sut, 0xff.into());
        assert_eq!(sut.value(), 0xff);
        assert_eq!(sut.describe_value(), "Erro fora do escopo de segurança");
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), [0xff]);
        assert_eq!(sut.to_string(), "0xff [Erro fora do escopo de segurança]");
    }

    #[test]
    fn value_unknown() {
        let sut: ErrorCode = [0x15].into();

        assert_eq!(sut, ErrorCode::Unknown(0x15));
        assert_eq!(sut, 0x15.into());
        assert_eq!(sut.value(), 0x15);
        assert_eq!(sut.describe_value(), "DESCONHECIDO");
        assert!(!sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x15]);
        assert_eq!(sut.to_string(), "0x15 [DESCONHECIDO]");
    }
}
