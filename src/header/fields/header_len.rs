use std::fmt;

/// Tamanho total do cabeçalho em bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderLen {
    Default,
    Unknown(u16),
}

impl From<[u8; 2]> for HeaderLen {
    fn from(value: [u8; 2]) -> Self {
        (((value[0] as u16) << 8) + (value[1] as u16)).into()
    }
}

impl From<u16> for HeaderLen {
    fn from(value: u16) -> Self {
        match value {
            0x024c => Self::Default,
            n => Self::Unknown(n),
        }
    }
}

impl HeaderLen {
    pub fn value(&self) -> u16 {
        match self {
            Self::Default => 0x024c,
            Self::Unknown(n) => *n,
        }
    }

    pub fn describe_value(&self) -> String {
        match self {
            Self::Default => "588".to_string(),
            Self::Unknown(n) => format!("{n} != 588"),
        }
    }

    pub fn is_valid(&self) -> bool {
        !matches!(self, Self::Unknown(_))
    }

    pub fn to_bytes(&self) -> [u8; 2] {
        let value = self.value();
        [(value >> 8) as u8, value as u8]
    }
}

impl fmt::Display for HeaderLen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = self.value();
        let desc = self.describe_value();
        write!(f, "0x{value:04x} [{desc}]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_zero() {
        let sut: HeaderLen = [0x00, 0x00].into();

        assert_eq!(sut, HeaderLen::Unknown(0x0000));
        assert_eq!(sut, 0x0000.into());
        assert_eq!(sut.value(), 0x0000);
        assert_eq!(sut.describe_value(), "0 != 588");
        assert!(!sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x00, 0x00]);
        assert_eq!(sut.to_string(), "0x0000 [0 != 588]");
    }

    #[test]
    fn value_default() {
        let sut: HeaderLen = [0x02, 0x4c].into();

        assert_eq!(sut, HeaderLen::Default);
        assert_eq!(sut, 0x024c.into());
        assert_eq!(sut.value(), 0x024c);
        assert_eq!(sut.describe_value(), "588");
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), [0x02, 0x4c]);
        assert_eq!(sut.to_string(), "0x024c [588]");
    }
}
