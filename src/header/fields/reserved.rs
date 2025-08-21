use std::fmt;

/// Reservado para uso futuro.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reserved {
    NoValue,
    Unknown(u8),
}

impl From<[u8; 1]> for Reserved {
    fn from(value: [u8; 1]) -> Self {
        value[0].into()
    }
}

impl From<u8> for Reserved {
    fn from(value: u8) -> Self {
        match value {
            0x00 => Self::NoValue,
            n => Self::Unknown(n),
        }
    }
}

impl Reserved {
    pub fn value(&self) -> u8 {
        match self {
            Self::NoValue => 0x00,
            Self::Unknown(n) => *n,
        }
    }

    pub fn describe_value(&self) -> String {
        match self {
            Self::NoValue => "-".to_string(),
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

impl fmt::Display for Reserved {
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
        let sut: Reserved = [0x00].into();

        assert_eq!(sut, Reserved::NoValue);
        assert_eq!(sut, 0x00.into());
        assert_eq!(sut.value(), 0x00);
        assert_eq!(sut.describe_value(), "-");
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x00]);
        assert_eq!(sut.to_string(), "0x00 [-]");
    }

    #[test]
    fn value_rsa_1024() {
        let sut: Reserved = [0x01].into();

        assert_eq!(sut, Reserved::Unknown(0x01));
        assert_eq!(sut, 0x01.into());
        assert_eq!(sut.value(), 0x01);
        assert_eq!(sut.describe_value(), "DESCONHECIDO");
        assert!(!sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x01]);
        assert_eq!(sut.to_string(), "0x01 [DESCONHECIDO]");
    }
}
