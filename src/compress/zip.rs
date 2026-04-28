use std::io::{Cursor, Read, Write};

use zip::{ZipArchive, ZipWriter, write::SimpleFileOptions};

use super::Compress;

/// Compressor usando zip.
#[derive(Debug)]
pub struct Zip {}

impl Zip {
    /// Inicia zip.
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for Zip {
    fn default() -> Self {
        Self::new()
    }
}

impl Compress for Zip {
    fn compress(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        let mut cursor = Cursor::new(Vec::new());
        let mut archive = ZipWriter::new(&mut cursor);
        archive
            .start_file(
                "content",
                SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Deflated)
                    .compression_level(Some(264)),
            )
            .map_err(|error| error.to_string())?;
        archive.write(data).map_err(|error| error.to_string())?;
        archive.finish().map_err(|error| error.to_string())?;
        Ok(cursor.into_inner())
    }

    fn decompress(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        let cursor = Cursor::new(data);
        let mut archive = ZipArchive::new(cursor).map_err(|error| error.to_string())?;
        let mut file = archive.by_index(0).map_err(|error| error.to_string())?;
        let mut buffer: Vec<u8> = Vec::new();
        file.read_to_end(&mut buffer)
            .map_err(|error| error.to_string())?;
        Ok(buffer)
    }
}

#[cfg(test)]
mod tests {
    use rand::RngExt;

    use super::*;

    #[test]
    fn compress_and_decompress() {
        let mut rng = rand::rng();
        let data: Vec<_> = (0..256).map(|_| rng.random()).collect();

        let sut = Zip::default();
        let compressed = sut.compress(&data).unwrap();

        assert_ne!(compressed, data);

        let decompressed = sut.decompress(&compressed).unwrap();

        assert_eq!(decompressed, data);
    }
}
