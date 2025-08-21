use std::fmt;

/// PC do certificado digital.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PcCert {
    SpbSerpro,
    SpbCertisign,
    PessoasFisicas,
    SpbSerasa,
    SpbCaixa,
    SpbValid,
    SpbSoluti,
    Unknown(u8),
}

impl From<[u8; 1]> for PcCert {
    fn from(value: [u8; 1]) -> Self {
        value[0].into()
    }
}

impl From<u8> for PcCert {
    fn from(value: u8) -> Self {
        match value {
            0x01 => Self::SpbSerpro,
            0x02 => Self::SpbCertisign,
            0x03 => Self::PessoasFisicas,
            0x04 => Self::SpbSerasa,
            0x05 => Self::SpbCaixa,
            0x06 => Self::SpbValid,
            0x07 => Self::SpbSoluti,
            n => Self::Unknown(n),
        }
    }
}

impl PcCert {
    pub fn value(&self) -> u8 {
        match self {
            Self::SpbSerpro => 0x01,
            Self::SpbCertisign => 0x02,
            Self::PessoasFisicas => 0x03,
            Self::SpbSerasa => 0x04,
            Self::SpbCaixa => 0x05,
            Self::SpbValid => 0x06,
            Self::SpbSoluti => 0x07,
            Self::Unknown(n) => *n,
        }
    }

    pub fn describe_value(&self) -> String {
        match self {
            Self::SpbSerpro => "SPB-Serpro".to_string(),
            Self::SpbCertisign => "SPB-Certisign".to_string(),
            Self::PessoasFisicas => "Pessoas Físicas".to_string(),
            Self::SpbSerasa => "SPB-Serasa".to_string(),
            Self::SpbCaixa => "SPB-CAIXA".to_string(),
            Self::SpbValid => "SPB-Valid".to_string(),
            Self::SpbSoluti => "SPB-Soluti".to_string(),
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

impl fmt::Display for PcCert {
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
    fn value_zero() {
        let sut: PcCert = [0x00].into();

        assert_eq!(sut, PcCert::Unknown(0x00));
        assert_eq!(sut, 0x00.into());
        assert_eq!(sut.value(), 0x00);
        assert_eq!(sut.describe_value(), "DESCONHECIDO");
        assert!(!sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x00]);
        assert_eq!(sut.to_string(), "0x00 [DESCONHECIDO]");
    }

    #[test]
    fn value_spb_serpro() {
        let sut: PcCert = [0x01].into();

        assert_eq!(sut, PcCert::SpbSerpro);
        assert_eq!(sut, 0x01.into());
        assert_eq!(sut.value(), 0x01);
        assert_eq!(sut.describe_value(), "SPB-Serpro");
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x01]);
        assert_eq!(sut.to_string(), "0x01 [SPB-Serpro]");
    }

    #[test]
    fn value_spb_certisign() {
        let sut: PcCert = [0x02].into();

        assert_eq!(sut, PcCert::SpbCertisign);
        assert_eq!(sut, 0x02.into());
        assert_eq!(sut.value(), 0x02);
        assert_eq!(sut.describe_value(), "SPB-Certisign");
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x02]);
        assert_eq!(sut.to_string(), "0x02 [SPB-Certisign]");
    }

    #[test]
    fn value_pessoas_fisicas() {
        let sut: PcCert = [0x03].into();

        assert_eq!(sut, PcCert::PessoasFisicas);
        assert_eq!(sut, 0x03.into());
        assert_eq!(sut.value(), 0x03);
        assert_eq!(sut.describe_value(), "Pessoas Físicas");
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x03]);
        assert_eq!(sut.to_string(), "0x03 [Pessoas Físicas]");
    }

    #[test]
    fn value_spb_serasa() {
        let sut: PcCert = [0x04].into();

        assert_eq!(sut, PcCert::SpbSerasa);
        assert_eq!(sut, 0x04.into());
        assert_eq!(sut.value(), 0x04);
        assert_eq!(sut.describe_value(), "SPB-Serasa");
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x04]);
        assert_eq!(sut.to_string(), "0x04 [SPB-Serasa]");
    }

    #[test]
    fn value_spb_caixa() {
        let sut: PcCert = [0x05].into();

        assert_eq!(sut, PcCert::SpbCaixa);
        assert_eq!(sut, 0x05.into());
        assert_eq!(sut.value(), 0x05);
        assert_eq!(sut.describe_value(), "SPB-CAIXA");
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x05]);
        assert_eq!(sut.to_string(), "0x05 [SPB-CAIXA]");
    }

    #[test]
    fn value_spb_valid() {
        let sut: PcCert = [0x06].into();

        assert_eq!(sut, PcCert::SpbValid);
        assert_eq!(sut, 0x06.into());
        assert_eq!(sut.value(), 0x06);
        assert_eq!(sut.describe_value(), "SPB-Valid");
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x06]);
        assert_eq!(sut.to_string(), "0x06 [SPB-Valid]");
    }

    #[test]
    fn value_spb_soluti() {
        let sut: PcCert = [0x07].into();

        assert_eq!(sut, PcCert::SpbSoluti);
        assert_eq!(sut, 0x07.into());
        assert_eq!(sut.value(), 0x07);
        assert_eq!(sut.describe_value(), "SPB-Soluti");
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x07]);
        assert_eq!(sut.to_string(), "0x07 [SPB-Soluti]");
    }

    #[test]
    fn value_unknown() {
        let sut: PcCert = [0x08].into();

        assert_eq!(sut, PcCert::Unknown(0x08));
        assert_eq!(sut, 0x08.into());
        assert_eq!(sut.value(), 0x08);
        assert_eq!(sut.describe_value(), "DESCONHECIDO");
        assert!(!sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x08]);
        assert_eq!(sut.to_string(), "0x08 [DESCONHECIDO]");
    }
}
