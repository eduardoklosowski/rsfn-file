use rsa::{
    BigUint, Pkcs1v15Encrypt, RsaPublicKey, pkcs1v15::VerifyingKey, sha2::Sha256,
    signature::Verifier, traits::PublicKeyParts,
};

/// Manipula criptografia RSA com chave pública.
pub struct RsaPublic {
    key: RsaPublicKey,
}

impl RsaPublic {
    /// Inicia RSA com chave pública.
    pub fn new(n: BigUint, e: BigUint) -> Result<Self, String> {
        RsaPublicKey::new(n, e)
            .map_err(|error| format!("Erro ao criar objeto da chave pública: {error}"))
            .map(|key| Self { key })
    }

    /// Tamanho da chave.
    pub fn bits(&self) -> usize {
        self.key.size() * 8
    }

    /// Criptografa dados.
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        let mut rng = rand::thread_rng();
        self.key
            .encrypt(&mut rng, Pkcs1v15Encrypt, data)
            .map_err(|error| format!("Erro na criptografia dos dados: {error}"))
    }

    /// Verifica assinatura dos dados.
    pub fn verify(&self, data: &[u8], sign: &[u8]) -> Result<(), String> {
        let key = VerifyingKey::<Sha256>::new(self.key.clone());
        let signature = match sign.try_into() {
            Ok(signature) => signature,
            Err(error) => {
                return Err(format!("Erro ao ler sinatura RSA: {error}"));
            }
        };
        key.verify(data, &signature)
            .map_err(|error| format!("Erro na validação da assinantura RSA: {error}"))
    }
}
