use rsa::{
    Pkcs1v15Encrypt, RsaPrivateKey,
    pkcs1::DecodeRsaPrivateKey,
    pkcs1v15::SigningKey,
    pkcs8::DecodePrivateKey,
    sha2::Sha256,
    signature::{RandomizedSigner, SignatureEncoding},
    traits::PublicKeyParts,
};

/// Manipula criptografia RSA com chave privada.
pub struct RsaPrivate {
    key: RsaPrivateKey,
}

impl RsaPrivate {
    /// Carrega chave privada RSA de arquivo PEM.
    pub fn load_pem(data: &str) -> Result<Self, String> {
        if data.starts_with("-----BEGIN PRIVATE KEY----") {
            RsaPrivateKey::from_pkcs8_pem(data)
                .map_err(|error| format!("Erro ao ler chave no formato PKCS#8: {error}"))
        } else if data.starts_with("-----BEGIN RSA PRIVATE KEY----") {
            RsaPrivateKey::from_pkcs1_pem(data)
                .map_err(|error| format!("Erro ao ler chave no formato PKCS#1: {error}"))
        } else {
            Err("Formato da chave RSA não reconhecido".to_string())
        }
        .map(|key| Self { key })
    }

    /// Tamanho da chave.
    pub fn bits(&self) -> usize {
        self.key.size() * 8
    }

    /// Descriptografa dados.
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        self.key
            .decrypt(Pkcs1v15Encrypt, data)
            .map_err(|error| format!("Erro na descriptografia dos dados: {error}"))
    }

    /// Assina dados.
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let key = SigningKey::<Sha256>::new(self.key.clone());
        key.sign_with_rng(&mut rng, data).to_bytes().into()
    }
}
