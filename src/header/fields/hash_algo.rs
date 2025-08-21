use std::fmt;

/// Algoritmo de "hash".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashAlgo {
    SHA1,
    SHA256,
    Unknown(u8),
}

impl From<[u8; 1]> for HashAlgo {
    fn from(value: [u8; 1]) -> Self {
        value[0].into()
    }
}

impl From<u8> for HashAlgo {
    fn from(value: u8) -> Self {
        match value {
            0x02 => Self::SHA1,
            0x03 => Self::SHA256,
            n => Self::Unknown(n),
        }
    }
}

impl HashAlgo {
    pub fn value(&self) -> u8 {
        match self {
            Self::SHA1 => 0x02,
            Self::SHA256 => 0x03,
            Self::Unknown(n) => *n,
        }
    }

    pub fn describe_value(&self) -> String {
        match self {
            Self::SHA1 => "SHA-1".to_string(),
            Self::SHA256 => "SHA-256".to_string(),
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

impl fmt::Display for HashAlgo {
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
        let sut: HashAlgo = [0x00].into();

        assert_eq!(sut, HashAlgo::Unknown(0x00));
        assert_eq!(sut, 0x00.into());
        assert_eq!(sut.value(), 0x00);
        assert_eq!(sut.describe_value(), "DESCONHECIDO");
        assert!(!sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x00]);
        assert_eq!(sut.to_string(), "0x00 [DESCONHECIDO]");
    }

    #[test]
    fn value_sha1() {
        let sut: HashAlgo = [0x02].into();

        assert_eq!(sut, HashAlgo::SHA1);
        assert_eq!(sut, 0x02.into());
        assert_eq!(sut.value(), 0x02);
        assert_eq!(sut.describe_value(), "SHA-1");
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x02]);
        assert_eq!(sut.to_string(), "0x02 [SHA-1]");
    }

    #[test]
    fn value_sha256() {
        let sut: HashAlgo = [0x03].into();

        assert_eq!(sut, HashAlgo::SHA256);
        assert_eq!(sut, 0x03.into());
        assert_eq!(sut.value(), 0x03);
        assert_eq!(sut.describe_value(), "SHA-256");
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x03]);
        assert_eq!(sut.to_string(), "0x03 [SHA-256]");
    }
}
