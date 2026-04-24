pub use self::aes256::Aes256;
pub use self::rsa::{RsaPrivate, RsaPublic};

mod aes256;
mod rsa;

pub fn load_key(data: &[u8]) -> Result<RsaPrivate, String> {
    let content = String::from_utf8(data.into())
        .map_err(|error| format!("Chave não está em UTF-8: {error}"))?;
    let key = RsaPrivate::load_pem(&content).map_err(|error| format!("Chave inválida: {error}"))?;
    Ok(key)
}
