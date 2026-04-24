pub mod gzip;
pub mod plain;
pub mod zip;

/// Algoritmo de compressão e descompressão.
pub trait Compress {
    /// Comprime dados.
    fn compress(&self, data: &[u8]) -> Result<Vec<u8>, String>;

    /// Descomprime dados.
    fn decompress(&self, data: &[u8]) -> Result<Vec<u8>, String>;
}

/// Algoritmos de compressão de dados.
#[derive(Debug, Default)]
pub enum Compressors {
    #[default]
    Plain,
    Gzip,
    Zip,
}

impl Compressors {
    pub fn init(&self) -> Box<dyn Compress> {
        match self {
            Self::Plain => Box::new(plain::Plain::default()),
            Self::Gzip => Box::new(gzip::Gzip::default()),
            Self::Zip => Box::new(zip::Zip::default()),
        }
    }

    pub fn try_decompress(data: &[u8]) -> Result<Vec<u8>, String> {
        if let Ok(plain) = Self::Zip.init().decompress(data) {
            return Ok(plain);
        }
        if let Ok(plain) = Self::Gzip.init().decompress(data) {
            return Ok(plain);
        }

        Self::Plain.init().decompress(data)
    }
}
