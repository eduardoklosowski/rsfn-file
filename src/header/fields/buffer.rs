use std::fmt;

/// Buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Buffer([u8; 256]);

impl TryFrom<Vec<u8>> for Buffer {
    type Error = Vec<u8>;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let value = value.try_into();
        Ok(Self(value?))
    }
}

impl From<[u8; 256]> for Buffer {
    fn from(value: [u8; 256]) -> Self {
        Self(value)
    }
}

impl Buffer {
    pub fn value(&self) -> [u8; 256] {
        self.0
    }

    pub fn describe_value(&self) -> String {
        let len = self
            .value()
            .iter()
            .zip(1..self.0.len() + 1)
            .rev()
            .filter_map(|(&b, i)| if b != 0 { Some(i) } else { None })
            .next()
            .unwrap_or(0);
        format!("len={len}")
    }

    pub fn is_valid(&self) -> bool {
        !self.0.iter().all(|&b| b == 0)
    }

    pub fn to_bytes(&self) -> [u8; 256] {
        self.value()
    }
}

impl fmt::Display for Buffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let desc = self.describe_value();
        write!(f, "blob [{desc}]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_zero() {
        let value = [0; 256];

        let sut: Buffer = (0..256).map(|_| 0).collect::<Vec<_>>().try_into().unwrap();

        assert_eq!(sut, Buffer(value));
        assert_eq!(sut, value.into());
        assert_eq!(sut.value(), value);
        assert_eq!(sut.describe_value(), "len=0");
        assert!(!sut.is_valid());
        assert_eq!(sut.to_bytes(), value);
        assert_eq!(sut.to_string(), "blob [len=0]");
    }

    #[test]
    fn value_some_bytes() {
        let mut value = [0; 256];
        for i in 0..8 {
            value[i as usize] = i;
        }
        let value = value;

        let sut: Buffer = value.into();

        assert_eq!(sut, Buffer(value));
        assert_eq!(sut, value.into());
        assert_eq!(sut.value(), value);
        assert_eq!(sut.describe_value(), "len=8");
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), value);
        assert_eq!(sut.to_string(), "blob [len=8]");
    }

    #[test]
    fn value_full() {
        let value: [u8; 256] = (0..=255).collect::<Vec<_>>().try_into().unwrap();

        let sut: Buffer = (0..=255).collect::<Vec<_>>().try_into().unwrap();

        assert_eq!(sut, Buffer(value));
        assert_eq!(sut, value.into());
        assert_eq!(sut.value(), value);
        assert_eq!(sut.describe_value(), "len=256");
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), value);
        assert_eq!(sut.to_string(), "blob [len=256]");
    }

    #[test]
    fn fail_on_short_vec() {
        let value: Vec<_> = (0..255).map(|_| 0).collect();

        TryInto::<Buffer>::try_into(value).unwrap_err();
    }
}
