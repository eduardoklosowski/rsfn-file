use std::fmt;

/// Série do certificado digital.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertSerial([u8; 32]);

impl From<[u8; 32]> for CertSerial {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl CertSerial {
    pub fn value(&self) -> [u8; 32] {
        self.0
    }

    fn trim_value(&self) -> Vec<u8> {
        self.value()
            .into_iter()
            .skip_while(|&byte| byte == 0 || byte == b'0')
            .collect()
    }

    pub fn describe_value(&self) -> String {
        match String::from_utf8(self.trim_value()) {
            Ok(value) if !value.is_empty() => format!("0x{}", value.to_lowercase()),
            Ok(_) | Err(_) => "INVÁLIDO".to_string(),
        }
    }

    pub fn is_valid(&self) -> bool {
        match String::from_utf8(self.trim_value()) {
            Ok(value) if !value.is_empty() => true,
            Ok(_) | Err(_) => false,
        }
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.value()
    }
}

impl fmt::Display for CertSerial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value: String = self.value().iter().map(|b| format!("{b:02x}")).collect();
        let desc = self.describe_value();
        write!(f, "0x{value} [{desc}]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_binary_zero() {
        let value = [0; 32];

        let sut: CertSerial = value.into();

        assert_eq!(sut, CertSerial(value));
        assert_eq!(sut, value.into());
        assert_eq!(sut.value(), value);
        assert_eq!(sut.describe_value(), "INVÁLIDO");
        assert!(!sut.is_valid());
        assert_eq!(sut.to_bytes(), value);
        assert_eq!(
            sut.to_string(),
            "0x0000000000000000000000000000000000000000000000000000000000000000 [INVÁLIDO]"
        );
    }

    #[test]
    fn value_ascii_zero() {
        let value = [b'0'; 32];

        let sut: CertSerial = value.into();

        assert_eq!(sut, CertSerial(value));
        assert_eq!(sut, value.into());
        assert_eq!(sut.value(), value);
        assert_eq!(sut.describe_value(), "INVÁLIDO");
        assert!(!sut.is_valid());
        assert_eq!(sut.to_bytes(), value);
        assert_eq!(
            sut.to_string(),
            "0x3030303030303030303030303030303030303030303030303030303030303030 [INVÁLIDO]"
        );
    }

    #[test]
    fn value_some_bytes() {
        let mut value = [0; 32];
        for i in 26..32 {
            value[i as usize] = b'1' + i - 26;
        }
        let value = value;

        let sut: CertSerial = value.into();

        assert_eq!(sut, CertSerial(value));
        assert_eq!(sut, value.into());
        assert_eq!(sut.value(), value);
        assert_eq!(sut.describe_value(), "0x123456");
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), value);
        assert_eq!(
            sut.to_string(),
            "0x0000000000000000000000000000000000000000000000000000313233343536 [0x123456]"
        );
    }

    #[test]
    fn value_invalid_bytes() {
        let value = [0xff; 32];

        let sut: CertSerial = value.into();

        assert_eq!(sut, CertSerial(value));
        assert_eq!(sut, value.into());
        assert_eq!(sut.value(), value);
        assert_eq!(sut.describe_value(), "INVÁLIDO");
        assert!(!sut.is_valid());
        assert_eq!(sut.to_bytes(), value);
        assert_eq!(
            sut.to_string(),
            "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff [INVÁLIDO]"
        );
    }

    #[test]
    fn value_full() {
        let value: [u8; 32] = (0..16)
            .flat_map(|byte| {
                format!("{byte:02X}")
                    .chars()
                    .map(|c| c as u8)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let sut: CertSerial = value.into();

        assert_eq!(sut, CertSerial(value));
        assert_eq!(sut, value.into());
        assert_eq!(sut.value(), value);
        assert_eq!(sut.describe_value(), "0x102030405060708090a0b0c0d0e0f");
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), value);
        assert_eq!(
            sut.to_string(),
            "0x3030303130323033303430353036303730383039304130423043304430453046 [0x102030405060708090a0b0c0d0e0f]"
        );
    }
}
