use rsa::BigUint;
use x509_certificate::{KeyAlgorithm, X509Certificate};

use crate::ciphers::RsaPublic;

#[derive(Debug)]
pub struct Certificate {
    pub cert: X509Certificate,
}

impl Certificate {
    pub fn load(data: &[u8]) -> Result<Self, String> {
        let cert = X509Certificate::from_pem(data).map_err(|error| error.to_string())?;
        Ok(Self { cert })
    }

    pub fn serial(&self) -> [u8; 32] {
        let mut output = [0; 32];
        let serial = self.cert.serial_number_asn1().as_slice();
        output[32 - serial.len()..32].copy_from_slice(serial);
        output
    }

    pub fn key_type(&self) -> Option<(KeyAlgorithm, usize)> {
        match self.cert.key_algorithm() {
            Some(KeyAlgorithm::Rsa) => {
                Some((KeyAlgorithm::Rsa, self.rsa_pub_key().unwrap().bits()))
            }
            Some(algo) => Some((algo, 0)),
            None => None,
        }
    }

    pub fn rsa_pub_key(&self) -> Result<RsaPublic, String> {
        let cert_pub_key = self
            .cert
            .rsa_public_key_data()
            .map_err(|error| error.to_string())?;
        RsaPublic::new(
            BigUint::from_bytes_be(cert_pub_key.modulus.as_slice()),
            BigUint::from_bytes_be(cert_pub_key.public_exponent.as_slice()),
        )
    }
}
