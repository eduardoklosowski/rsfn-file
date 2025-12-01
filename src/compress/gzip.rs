use std::io::{Read, Write};

use libflate::gzip;

use super::Compress;

/// Compressor usando gzip.
#[derive(Debug)]
pub struct Gzip {}

impl Gzip {
    /// Inicia gzip.
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for Gzip {
    fn default() -> Self {
        Self::new()
    }
}

impl Compress for Gzip {
    fn compress(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        let mut encoder = gzip::Encoder::new(Vec::new())
            .map_err(|error| format!("Falha ao iniciar o gzip: {error}"))?;
        encoder
            .write_all(data)
            .map_err(|error| format!("Falha na compactação do gzip: {error}"))?;
        encoder
            .finish()
            .into_result()
            .map_err(|error| format!("Falha na finalização do gzip: {error}"))
    }

    fn decompress(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        let mut decoder = gzip::Decoder::new(data)
            .map_err(|error| format!("Falha ao iniciar o gzip: {error}"))?;
        let mut text = Vec::new();
        decoder
            .read_to_end(&mut text)
            .map_err(|error| format!("Falha na descompactação do gzip: {error}"))?;
        Ok(text)
    }
}

#[cfg(test)]
mod tests {
    use rand::Rng;

    use super::*;

    #[test]
    fn compress_and_decompress() {
        let mut rng = rand::rng();
        let data: Vec<_> = (0..256).map(|_| rng.random()).collect();

        let sut = Gzip::default();
        let compressed = sut.compress(&data).unwrap();

        assert_ne!(compressed, data);

        let decompressed = sut.decompress(&compressed).unwrap();

        assert_eq!(decompressed, data);
    }
}
