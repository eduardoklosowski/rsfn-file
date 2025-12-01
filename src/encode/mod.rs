pub mod plain;
pub mod utf16be;

/// Algoritmo de codificação e decodificação.
pub trait Encode {
    /// Codifica os dados.
    fn encode(&self, data: &[u8]) -> Result<Vec<u8>, String>;

    /// Decodifica os dados.
    fn decode(&self, data: &[u8]) -> Result<Vec<u8>, String>;
}

/// Algoritmos de codificação de dados.
#[derive(Debug, Default)]
pub enum Encoders {
    Plain,
    #[default]
    Utf16be,
}

impl Encoders {
    pub fn init(&self) -> Box<dyn Encode> {
        match self {
            Self::Plain => Box::new(plain::Plain::default()),
            Self::Utf16be => Box::new(utf16be::Utf16be::default()),
        }
    }
}
