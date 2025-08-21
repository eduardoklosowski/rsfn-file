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

    pub fn describe_value(&self) -> String {
        self.value()
            .iter()
            .skip_while(|&&b| b == 0)
            .map(|&b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    }

    pub fn is_valid(&self) -> bool {
        !self.0.iter().all(|&b| b == 0)
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
    fn value_zero() {
        let value = [0; 32];

        let sut: CertSerial = [0; 32].into();

        assert_eq!(sut, CertSerial(value));
        assert_eq!(sut, value.into());
        assert_eq!(sut.value(), value);
        assert_eq!(sut.describe_value(), "");
        assert!(!sut.is_valid());
        assert_eq!(sut.to_bytes(), value);
        assert_eq!(
            sut.to_string(),
            "0x0000000000000000000000000000000000000000000000000000000000000000 []"
        );
    }

    #[test]
    fn value_some_bytes() {
        let mut value = [0; 32];
        for i in 26..32 {
            value[i as usize] = i;
        }
        let value = value;

        let sut: CertSerial = value.into();

        assert_eq!(sut, CertSerial(value));
        assert_eq!(sut, value.into());
        assert_eq!(sut.value(), value);
        assert_eq!(sut.describe_value(), "1a:1b:1c:1d:1e:1f");
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), value);
        assert_eq!(
            sut.to_string(),
            "0x00000000000000000000000000000000000000000000000000001a1b1c1d1e1f [1a:1b:1c:1d:1e:1f]"
        );
    }

    #[test]
    fn value_full() {
        let value: [u8; 32] = (0..32).collect::<Vec<_>>().try_into().unwrap();

        let sut: CertSerial = value.into();

        assert_eq!(sut, CertSerial(value));
        assert_eq!(sut, value.into());
        assert_eq!(sut.value(), value);
        assert_eq!(
            sut.describe_value(),
            "01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f"
        );
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), value);
        assert_eq!(
            sut.to_string(),
            "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f [01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f]"
        );
    }
}
