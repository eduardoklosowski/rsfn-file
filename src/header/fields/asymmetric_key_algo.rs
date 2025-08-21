use std::fmt;

/// Algoritmo da chave assimétrica.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AsymmetricKeyAlgo {
    RSA1024,
    RSA2048,
    Unknown(u8),
}

impl From<[u8; 1]> for AsymmetricKeyAlgo {
    fn from(value: [u8; 1]) -> Self {
        value[0].into()
    }
}

impl From<u8> for AsymmetricKeyAlgo {
    fn from(value: u8) -> Self {
        match value {
            0x01 => Self::RSA1024,
            0x02 => Self::RSA2048,
            n => Self::Unknown(n),
        }
    }
}

impl AsymmetricKeyAlgo {
    pub fn value(&self) -> u8 {
        match self {
            Self::RSA1024 => 0x01,
            Self::RSA2048 => 0x02,
            Self::Unknown(n) => *n,
        }
    }

    pub fn describe_value(&self) -> String {
        match self {
            Self::RSA1024 => "RSA com 1024 bits".to_string(),
            Self::RSA2048 => "RSA com 2048 bits".to_string(),
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

impl fmt::Display for AsymmetricKeyAlgo {
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
        let sut: AsymmetricKeyAlgo = [0x00].into();

        assert_eq!(sut, AsymmetricKeyAlgo::Unknown(0x00));
        assert_eq!(sut, 0x00.into());
        assert_eq!(sut.value(), 0x00);
        assert_eq!(sut.describe_value(), "DESCONHECIDO");
        assert!(!sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x00]);
        assert_eq!(sut.to_string(), "0x00 [DESCONHECIDO]");
    }

    #[test]
    fn value_rsa_1024() {
        let sut: AsymmetricKeyAlgo = [0x01].into();

        assert_eq!(sut, AsymmetricKeyAlgo::RSA1024);
        assert_eq!(sut, 0x01.into());
        assert_eq!(sut.value(), 0x01);
        assert_eq!(sut.describe_value(), "RSA com 1024 bits");
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x01]);
        assert_eq!(sut.to_string(), "0x01 [RSA com 1024 bits]");
    }

    #[test]
    fn value_rsa_2048() {
        let sut: AsymmetricKeyAlgo = [0x02].into();

        assert_eq!(sut, AsymmetricKeyAlgo::RSA2048);
        assert_eq!(sut, 0x02.into());
        assert_eq!(sut.value(), 0x02);
        assert_eq!(sut.describe_value(), "RSA com 2048 bits");
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x02]);
        assert_eq!(sut.to_string(), "0x02 [RSA com 2048 bits]");
    }
}
