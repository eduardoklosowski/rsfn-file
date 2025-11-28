use std::fmt;

use super::Buffer;

/// Buffer que pode ser vazio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NullableBuffer {
    None,
    Some(Box<Buffer>),
}

impl TryFrom<Vec<u8>> for NullableBuffer {
    type Error = Vec<u8>;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let value: [u8; 256] = value.try_into()?;
        Ok(value.into())
    }
}

impl From<[u8; 256]> for NullableBuffer {
    fn from(value: [u8; 256]) -> Self {
        if value.iter().all(|&byte| byte == 0) {
            Self::None
        } else {
            Self::Some(Box::new(value.into()))
        }
    }
}

impl NullableBuffer {
    pub fn value(&self) -> [u8; 256] {
        match self {
            Self::None => [0; 256],
            Self::Some(buffer) => buffer.value(),
        }
    }

    pub fn describe_value(&self) -> String {
        match self {
            Self::None => "VAZIO".to_string(),
            Self::Some(buffer) => buffer.describe_value(),
        }
    }

    pub fn is_valid(&self) -> bool {
        true
    }

    pub fn to_bytes(&self) -> [u8; 256] {
        self.value()
    }
}

impl fmt::Display for NullableBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::None => self.describe_value(),
                Self::Some(buffer) => buffer.to_string(),
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_zero() {
        let value = [0; 256];

        let sut: NullableBuffer = (0..256).map(|_| 0).collect::<Vec<_>>().try_into().unwrap();

        assert_eq!(sut, NullableBuffer::None);
        assert_eq!(sut, value.into());
        assert_eq!(sut.value(), value);
        assert_eq!(sut.describe_value(), "VAZIO");
        assert!(sut.is_valid());
        assert_eq!(sut.to_bytes(), value);
        assert_eq!(sut.to_string(), "VAZIO");
    }

    #[test]
    fn value_some_bytes() {
        let mut value = [0; 256];
        for i in 0..8 {
            value[i as usize] = i;
        }
        let value = value;

        let sut: NullableBuffer = value.into();

        assert_eq!(sut, NullableBuffer::Some(Box::new(value.into())));
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

        let sut: NullableBuffer = (0..=255).collect::<Vec<_>>().try_into().unwrap();

        assert_eq!(sut, NullableBuffer::Some(Box::new(value.into())));
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

        TryInto::<NullableBuffer>::try_into(value).unwrap_err();
    }
}
