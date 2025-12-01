use crate::encode::Encode;

/// Dados em UTF-16BE.
#[derive(Debug)]
pub struct Utf16be {}

impl Utf16be {
    /// Inicia não codificador de dados.
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for Utf16be {
    fn default() -> Self {
        Self::new()
    }
}

impl Encode for Utf16be {
    fn encode(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        let text = String::from_utf8(data.into())
            .map_err(|error| format!("Falha ao ler dados como UTF-8: {error}"))?;
        Ok(text.encode_utf16().flat_map(u16::to_be_bytes).collect())
    }

    fn decode(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        let data: Vec<_> = data
            .chunks_exact(2)
            .map(|bytes| {
                u16::from_be_bytes(
                    bytes
                        .try_into()
                        .expect("Tamanho de dados inválido para UTF-16BE"),
                )
            })
            .collect();
        let text = String::from_utf16(&data)
            .map_err(|error| format!("Falha ao ler dados como UTF-16BE: {error}"))?;
        Ok(text.bytes().collect())
    }
}

#[cfg(test)]
mod tests {
    use rand::Rng;

    use super::*;

    #[test]
    fn compress_and_decompress() {
        let mut rng = rand::rng();
        let data: Vec<char> = (0..256).map(|_| rng.random()).collect();
        let data = String::from_iter(data);
        let data = data.as_bytes();

        let sut = Utf16be::default();
        let compressed = sut.encode(data).unwrap();

        assert_ne!(compressed, data);

        let decompressed = sut.decode(&compressed).unwrap();

        assert_eq!(decompressed, data);
    }
}
