use crate::encode::Encode;

/// Dados sem codificação.
#[derive(Debug)]
pub struct Plain {}

impl Plain {
    /// Inicia não codificador de dados.
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for Plain {
    fn default() -> Self {
        Self::new()
    }
}

impl Encode for Plain {
    fn encode(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        Ok(data.into())
    }

    fn decode(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        Ok(data.into())
    }
}

#[cfg(test)]
mod tests {
    use rand::Rng;

    use super::*;

    #[test]
    fn encode() {
        let mut rng = rand::rng();
        let data: Vec<_> = (0..256).map(|_| rng.random()).collect();

        let sut = Plain::default();
        let returned = sut.encode(&data).unwrap();

        assert_eq!(returned, data);
    }

    #[test]
    fn decode() {
        let mut rng = rand::rng();
        let data: Vec<_> = (0..256).map(|_| rng.random()).collect();

        let sut = Plain::default();
        let returned = sut.decode(&data).unwrap();

        assert_eq!(returned, data);
    }
}
