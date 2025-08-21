use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, AeadCore, Key, KeyInit, Nonce, OsRng},
};

/// Manipula criptografia AES 256 GCM.
pub struct Aes256 {
    key: Key<Aes256Gcm>,
    iv: Nonce<Aes256Gcm>,
    cipher: Aes256Gcm,
}

impl Aes256 {
    /// Inicia AES 256 a partir da chave. Recebe um vetor contendo chave e IV.
    pub fn new(data: &[u8]) -> Self {
        let mut key = [0; 32];
        key.clone_from_slice(&data[0..32]);
        let mut iv = [0; 12];
        iv.clone_from_slice(&data[32..44]);

        let key = key.into();
        let iv = iv.into();
        Self {
            key,
            iv,
            cipher: Aes256Gcm::new(&key),
        }
    }

    /// Inicia AES 256 gerando uma chave nova.
    pub fn generate_new_key() -> Self {
        let key = Aes256Gcm::generate_key(OsRng);
        let iv = Aes256Gcm::generate_nonce(OsRng);
        Self {
            key,
            iv,
            cipher: Aes256Gcm::new(&key),
        }
    }

    /// Exporta chave e IV do AES 256.
    pub fn export_key(&self) -> Vec<u8> {
        let data: [&[u8]; _] = [&self.key, &self.iv];
        data.concat()
    }

    /// Criptografa dados.
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        self.cipher
            .encrypt(&self.iv, data)
            .map_err(|error| error.to_string())
    }

    /// Descriptografa dados.
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        self.cipher
            .decrypt(&self.iv, data)
            .map_err(|error| error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use rand::Rng;

    use super::*;

    #[test]
    fn encrypt_decrypt_with_generated_key() {
        let mut rng = rand::rng();
        let data: Vec<_> = (0..256).map(|_| rng.random()).collect();

        let sut = Aes256::generate_new_key();
        let crypted = sut.encrypt(&data).unwrap();

        assert_ne!(crypted, data);

        let plain = sut.decrypt(&crypted).unwrap();

        assert_eq!(plain, data);
    }

    #[test]
    fn export_import_key() {
        let mut rng = rand::rng();
        let data: Vec<_> = (0..256).map(|_| rng.random()).collect();

        let sut = Aes256::generate_new_key();
        let crypted = sut.encrypt(&data).unwrap();

        let sut2 = Aes256::new(&sut.export_key());
        let plain = sut2.decrypt(&crypted).unwrap();

        assert_eq!(plain, data);
    }
}
