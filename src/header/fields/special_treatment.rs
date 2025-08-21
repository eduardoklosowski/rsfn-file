use std::fmt;

/// Indicador de tratamento especial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpecialTreatment {
    Normal,
    UsingNotEnabledCert,
    NotCryptBroadcast,
    NotCrypt,
    NotCompress,
    NotCompressAndNotCrypt,
    Compress,
    ComrpessWithoutCrypt,
    Unknown(u8),
}

impl From<[u8; 1]> for SpecialTreatment {
    fn from(value: [u8; 1]) -> Self {
        value[0].into()
    }
}

impl From<u8> for SpecialTreatment {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Normal,
            1 => Self::UsingNotEnabledCert,
            2 => Self::NotCryptBroadcast,
            3 => Self::NotCrypt,
            4 => Self::NotCompress,
            6 => Self::NotCompressAndNotCrypt,
            8 => Self::Compress,
            10 => Self::ComrpessWithoutCrypt,
            n => Self::Unknown(n),
        }
    }
}

impl SpecialTreatment {
    pub fn value(&self) -> u8 {
        match self {
            Self::Normal => 0,
            Self::UsingNotEnabledCert => 1,
            Self::NotCryptBroadcast => 2,
            Self::NotCrypt => 3,
            Self::NotCompress => 4,
            Self::NotCompressAndNotCrypt => 6,
            Self::Compress => 8,
            Self::ComrpessWithoutCrypt => 10,
            Self::Unknown(n) => *n,
        }
    }

    pub fn describe_value(&self) -> String {
        match self {
            Self::Normal => "Uso normal".to_string(),
            Self::UsingNotEnabledCert => {
                "Utiliza um certificado digital ainda não ativado".to_string()
            }
            Self::NotCryptBroadcast => "Não cifrada para o destinatário (broadcast)".to_string(),
            Self::NotCrypt => "Não cifrada que pode ser relativa à segurança".to_string(),
            Self::NotCompress => "Arquivo não compactado".to_string(),
            Self::NotCompressAndNotCrypt => "Arquivo não compactado e sem cifragem".to_string(),
            Self::Compress => "Arquivo compactado".to_string(),
            Self::ComrpessWithoutCrypt => "Arquivo compactado sem cifragem".to_string(),
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

impl fmt::Display for SpecialTreatment {
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
    fn value_normal() {
        let sut: SpecialTreatment = [0].into();

        assert_eq!(sut, SpecialTreatment::Normal);
        assert_eq!(sut, 0.into());
        assert_eq!(sut.value(), 0);
        assert_eq!(sut.describe_value(), "Uso normal");
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), [0]);
        assert_eq!(sut.to_string(), "0x00 [Uso normal]");
    }

    #[test]
    fn value_using_not_enabled_cert() {
        let sut: SpecialTreatment = [1].into();

        assert_eq!(sut, SpecialTreatment::UsingNotEnabledCert);
        assert_eq!(sut, 1.into());
        assert_eq!(sut.value(), 1);
        assert_eq!(
            sut.describe_value(),
            "Utiliza um certificado digital ainda não ativado"
        );
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), [1]);
        assert_eq!(
            sut.to_string(),
            "0x01 [Utiliza um certificado digital ainda não ativado]"
        );
    }

    #[test]
    fn value_not_crypt_broadcast() {
        let sut: SpecialTreatment = [2].into();

        assert_eq!(sut, SpecialTreatment::NotCryptBroadcast);
        assert_eq!(sut, 2.into());
        assert_eq!(sut.value(), 2);
        assert_eq!(
            sut.describe_value(),
            "Não cifrada para o destinatário (broadcast)"
        );
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), [2]);
        assert_eq!(
            sut.to_string(),
            "0x02 [Não cifrada para o destinatário (broadcast)]"
        );
    }

    #[test]
    fn value_not_crypt() {
        let sut: SpecialTreatment = [3].into();

        assert_eq!(sut, SpecialTreatment::NotCrypt);
        assert_eq!(sut, 3.into());
        assert_eq!(sut.value(), 3);
        assert_eq!(
            sut.describe_value(),
            "Não cifrada que pode ser relativa à segurança"
        );
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), [3]);
        assert_eq!(
            sut.to_string(),
            "0x03 [Não cifrada que pode ser relativa à segurança]"
        );
    }

    #[test]
    fn value_not_compress() {
        let sut: SpecialTreatment = [4].into();

        assert_eq!(sut, SpecialTreatment::NotCompress);
        assert_eq!(sut, 4.into());
        assert_eq!(sut.value(), 4);
        assert_eq!(sut.describe_value(), "Arquivo não compactado");
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), [4]);
        assert_eq!(sut.to_string(), "0x04 [Arquivo não compactado]");
    }

    #[test]
    fn value_not_compress_and_not_crypt() {
        let sut: SpecialTreatment = [6].into();

        assert_eq!(sut, SpecialTreatment::NotCompressAndNotCrypt);
        assert_eq!(sut, 6.into());
        assert_eq!(sut.value(), 6);
        assert_eq!(
            sut.describe_value(),
            "Arquivo não compactado e sem cifragem"
        );
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), [6]);
        assert_eq!(
            sut.to_string(),
            "0x06 [Arquivo não compactado e sem cifragem]"
        );
    }

    #[test]
    fn value_compress() {
        let sut: SpecialTreatment = [8].into();

        assert_eq!(sut, SpecialTreatment::Compress);
        assert_eq!(sut, 8.into());
        assert_eq!(sut.value(), 8);
        assert_eq!(sut.describe_value(), "Arquivo compactado");
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), [8]);
        assert_eq!(sut.to_string(), "0x08 [Arquivo compactado]");
    }

    #[test]
    fn value_compress_without_crypt() {
        let sut: SpecialTreatment = [10].into();

        assert_eq!(sut, SpecialTreatment::ComrpessWithoutCrypt);
        assert_eq!(sut, 10.into());
        assert_eq!(sut.value(), 10);
        assert_eq!(sut.describe_value(), "Arquivo compactado sem cifragem");
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), [10]);
        assert_eq!(sut.to_string(), "0x0a [Arquivo compactado sem cifragem]");
    }

    #[test]
    fn value_unknown() {
        let sut: SpecialTreatment = [11].into();

        assert_eq!(sut, SpecialTreatment::Unknown(11));
        assert_eq!(sut, 11.into());
        assert_eq!(sut.value(), 11);
        assert_eq!(sut.describe_value(), "DESCONHECIDO");
        assert!(!sut.is_valid());
        assert_eq!(sut.to_bytes(), [11]);
        assert_eq!(sut.to_string(), "0x0b [DESCONHECIDO]");
    }
}
