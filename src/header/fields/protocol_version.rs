use std::fmt;

/// Versão do protocolo de segurança.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolVersion {
    Plain,
    Version2,
    Version3,
    Unknown(u8),
}

impl From<[u8; 1]> for ProtocolVersion {
    fn from(value: [u8; 1]) -> Self {
        value[0].into()
    }
}

impl From<u8> for ProtocolVersion {
    fn from(value: u8) -> Self {
        match value {
            0x00 => Self::Plain,
            0x02 => Self::Version2,
            0x03 => Self::Version3,
            n => Self::Unknown(n),
        }
    }
}

impl ProtocolVersion {
    pub fn value(&self) -> u8 {
        match self {
            Self::Plain => 0x00,
            Self::Version2 => 0x02,
            Self::Version3 => 0x03,
            Self::Unknown(n) => *n,
        }
    }

    pub fn describe_value(&self) -> String {
        match self {
            Self::Plain => "Em claro".to_string(),
            Self::Version2 => "Segunda versão".to_string(),
            Self::Version3 => "Terceira versão".to_string(),
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

impl fmt::Display for ProtocolVersion {
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
    fn value_plain() {
        let sut: ProtocolVersion = [0x00].into();

        assert_eq!(sut, ProtocolVersion::Plain);
        assert_eq!(sut, 0x00.into());
        assert_eq!(sut.value(), 0x00);
        assert_eq!(sut.describe_value(), "Em claro");
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x00]);
        assert_eq!(sut.to_string(), "0x00 [Em claro]");
    }

    #[test]
    fn value_version_2() {
        let sut: ProtocolVersion = [0x02].into();

        assert_eq!(sut, ProtocolVersion::Version2);
        assert_eq!(sut, 0x02.into());
        assert_eq!(sut.value(), 0x02);
        assert_eq!(sut.describe_value(), "Segunda versão");
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x02]);
        assert_eq!(sut.to_string(), "0x02 [Segunda versão]");
    }

    #[test]
    fn value_version_3() {
        let sut: ProtocolVersion = [0x03].into();

        assert_eq!(sut, ProtocolVersion::Version3);
        assert_eq!(sut, 0x03.into());
        assert_eq!(sut.value(), 0x03);
        assert_eq!(sut.describe_value(), "Terceira versão");
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x03]);
        assert_eq!(sut.to_string(), "0x03 [Terceira versão]");
    }

    #[test]
    fn value_unknown() {
        let sut: ProtocolVersion = [0x04].into();

        assert_eq!(sut, ProtocolVersion::Unknown(0x04));
        assert_eq!(sut, 0x04.into());
        assert_eq!(sut.value(), 0x04);
        assert_eq!(sut.describe_value(), "DESCONHECIDO");
        assert!(!sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x04]);
        assert_eq!(sut.to_string(), "0x04 [DESCONHECIDO]");
    }
}
