use std::fmt;

/// Algoritmo da chave simétrica.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SymmetricKeyAlgo {
    TripleDes,
    Aes,
    Unknown(u8),
}

impl From<[u8; 1]> for SymmetricKeyAlgo {
    fn from(value: [u8; 1]) -> Self {
        value[0].into()
    }
}

impl From<u8> for SymmetricKeyAlgo {
    fn from(value: u8) -> Self {
        match value {
            0x01 => Self::TripleDes,
            0x02 => Self::Aes,
            n => Self::Unknown(n),
        }
    }
}

impl SymmetricKeyAlgo {
    pub fn value(&self) -> u8 {
        match self {
            Self::TripleDes => 0x01,
            Self::Aes => 0x02,
            Self::Unknown(n) => *n,
        }
    }

    pub fn describe_value(&self) -> String {
        match self {
            Self::TripleDes => "Triple-DES com 168 bits (3 x 56 bits)".to_string(),
            Self::Aes => "AES com 256 bits".to_string(),
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

impl fmt::Display for SymmetricKeyAlgo {
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
        let sut: SymmetricKeyAlgo = [0x00].into();

        assert_eq!(sut, SymmetricKeyAlgo::Unknown(0x00));
        assert_eq!(sut, 0x00.into());
        assert_eq!(sut.value(), 0x00);
        assert_eq!(sut.describe_value(), "DESCONHECIDO");
        assert!(!sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x00]);
        assert_eq!(sut.to_string(), "0x00 [DESCONHECIDO]");
    }

    #[test]
    fn value_triple_des() {
        let sut: SymmetricKeyAlgo = [0x01].into();

        assert_eq!(sut, SymmetricKeyAlgo::TripleDes);
        assert_eq!(sut, 0x01.into());
        assert_eq!(sut.value(), 0x01);
        assert_eq!(
            sut.describe_value(),
            "Triple-DES com 168 bits (3 x 56 bits)"
        );
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x01]);
        assert_eq!(
            sut.to_string(),
            "0x01 [Triple-DES com 168 bits (3 x 56 bits)]"
        );
    }

    #[test]
    fn value_aes() {
        let sut: SymmetricKeyAlgo = [0x02].into();

        assert_eq!(sut, SymmetricKeyAlgo::Aes);
        assert_eq!(sut, 0x02.into());
        assert_eq!(sut.value(), 0x02);
        assert_eq!(sut.describe_value(), "AES com 256 bits");
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x02]);
        assert_eq!(sut.to_string(), "0x02 [AES com 256 bits]");
    }

    #[test]
    fn value_unknown() {
        let sut: SymmetricKeyAlgo = [0x03].into();

        assert_eq!(sut, SymmetricKeyAlgo::Unknown(0x03));
        assert_eq!(sut, 0x03.into());
        assert_eq!(sut.value(), 0x03);
        assert_eq!(sut.describe_value(), "DESCONHECIDO");
        assert!(!sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x03]);
        assert_eq!(sut.to_string(), "0x03 [DESCONHECIDO]");
    }
}
