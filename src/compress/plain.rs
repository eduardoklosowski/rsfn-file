use super::Compress;

/// Dados sem compressão.
#[derive(Debug)]
pub struct Plain {}

impl Plain {
    /// Inicia dados sem compressão.
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for Plain {
    fn default() -> Self {
        Self::new()
    }
}

impl Compress for Plain {
    fn compress(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        Ok(data.into())
    }

    fn decompress(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        Ok(data.into())
    }
}

#[cfg(test)]
mod tests {
    use rand::Rng;

    use super::*;

    #[test]
    fn compress() {
        let mut rng = rand::rng();
        let data: Vec<_> = (0..256).map(|_| rng.random()).collect();

        let sut = Plain::default();
        let returned = sut.compress(&data).unwrap();

        assert_eq!(returned, data);
    }

    #[test]
    fn decompress() {
        let mut rng = rand::rng();
        let data: Vec<_> = (0..256).map(|_| rng.random()).collect();

        let sut = Plain::default();
        let returned = sut.decompress(&data).unwrap();

        assert_eq!(returned, data);
    }
}
