use rsa::BigUint;
use x509_certificate::{KeyAlgorithm, X509Certificate};

use crate::{
    ciphers::RsaPublic,
    header::{AsymmetricKeyAlgo, CertSerial, PcCert},
};

#[derive(Debug)]
pub struct Certificate {
    pub cert: X509Certificate,
}

impl Certificate {
    pub fn load(data: &[u8]) -> Result<Self, String> {
        let cert = X509Certificate::from_pem(data).map_err(|error| error.to_string())?;
        Ok(Self { cert })
    }

    pub fn serial(&self) -> CertSerial {
        let mut output = [0; 32];
        let serial = self.cert.serial_number_asn1().as_slice();
        output[32 - serial.len()..32].copy_from_slice(serial);
        for i in 16..32 {
            let byte: [_; 2] = format!("{:02X}", output[i])
                .chars()
                .map(|c| c as u8)
                .collect::<Vec<_>>()
                .try_into()
                .expect("Erro ao converter bytes do serial do certificado");
            let j = (i - 16) * 2;
            output[j] = byte[0];
            output[j + 1] = byte[1];
        }
        output.into()
    }

    pub fn issuer(&self) -> PcCert {
        match self.cert.issuer_common_name() {
            Some(name) => match name.to_lowercase() {
                name if name.contains("serpro") => PcCert::SpbSerpro,
                name if name.contains("certisign") => PcCert::SpbCertisign,
                name if name.contains("serasa") => PcCert::SpbSerasa,
                name if name.contains("caixa") => PcCert::SpbCaixa,
                name if name.contains("valid") => PcCert::SpbValid,
                name if name.contains("soluti") => PcCert::SpbSoluti,
                _ => PcCert::Unknown(0),
            },
            None => PcCert::Unknown(0),
        }
    }

    pub fn key_type(&self) -> Result<AsymmetricKeyAlgo, String> {
        match self.cert.key_algorithm() {
            Some(KeyAlgorithm::Rsa) => match self.rsa_pub_key()?.bits() {
                1024 => Ok(AsymmetricKeyAlgo::RSA1024),
                2048 => Ok(AsymmetricKeyAlgo::RSA2048),
                bits => Err(format!("Chave RSA com {bits} bits não suportada")),
            },
            Some(algo) => Err(format!("Algoritmo {algo} não suportado")),
            None => Err("Não foi encontrada chave pública no certificado".to_string()),
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

pub fn load_cert_and_key(
    data: &[u8],
) -> Result<(Certificate, AsymmetricKeyAlgo, RsaPublic), String> {
    let certificate =
        Certificate::load(data).map_err(|error| format!("Certificado inválido: {error}"))?;
    let key_type = certificate
        .key_type()
        .map_err(|error| format!("Falha no tipo da chave do certificado: {error}"))?;
    let certificate_key = match key_type {
        AsymmetricKeyAlgo::RSA1024 | AsymmetricKeyAlgo::RSA2048 => certificate
            .rsa_pub_key()
            .map_err(|error| format!("Falha ao carregar chave RSA: {error}"))?,
        _ => Err(format!(
            "Sem implementação para chave {}",
            key_type.describe_value()
        ))?,
    };
    Ok((certificate, key_type, certificate_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_cert() {
        let sut = Certificate::load(
            b"-----BEGIN CERTIFICATE-----
MIIC8zCCAdugAwIBAgIIIH1C6IXcn6kwDQYJKoZIhvcNAQELBQAwGTEXMBUGA1UE
AwwOQUMgc2VycHJvIEZha2UwHhcNMjUwOTMwMDIyNjU4WhcNMjYwOTMwMDIyNjU4
WjAWMRQwEgYDVQQDDAtwYXJ0LWEgRmFrZTCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBAJIrnhP2PKGnoW/rbu+5ael1e7ZXgHwxxXW3cEuypxes6LeeOHEt
p7wquYfiCPkszC8wMCftafAlew/cOjqallRuMNdZxcn1recXlHKXLU0jvBz6nm78
sOAlfvmdI8rfbBo7yBktJHTvXFfCvzg0lylMmpJ0/lTc+T0TOoA8ob+24x8swGWR
gvWY6WLGP3oajP5xGJu2YveRYbEOFzgN+F1WPfKfZJB4mdNC+cOR2t7xLv7Koy8I
8/lU7sboITCsBDibnFoKB4L9xbZoYNm00mbinJT5iuMICeiVJJiSNbZdKqh0O3Ld
iIxBRgiD9ITEEBNfVDM1ZNi9/kTFGMwUbnECAwEAAaNCMEAwHQYDVR0OBBYEFLRu
bfdsjdj4Mf1YQ/w3OM35eaQzMB8GA1UdIwQYMBaAFP8850GObq5+0vgS9yZCTCZO
UdoxMA0GCSqGSIb3DQEBCwUAA4IBAQBvnKPGhNJzg+k4PyOsaKZBJLErS9gGUNrt
WZd/Sbs82auFZ6XVwzCNmxF5r6W0TWA2wscZayBJRl6UulmjuK2rc8KQakoqTwEa
YBbR7Ysywbr/Mt3JDWLrkBA5S7UyqJepEEZZsCV/Jg4mMF3bD+98+98dXmVfkgNI
A+S44Hp7Wx79SnhISdIVBe0aVjSrZG7GU4bxnzJmZ6VMbn3sO77MOPENolLYclse
5qNaqirT9FlqeIWe1dnt/4y2ZYB0VAEHGalO1FIy+e5DmdtbJpAhr641Kq55X5OE
B0XwnaTZBfQnhOO+H3cTDUEbOC95IhD8O1qYYP/LEnrW8n9cdp3w
-----END CERTIFICATE-----",
        )
        .unwrap();

        assert_eq!(sut.serial(), (*b"0000000000000000207D42E885DC9FA9").into());
        assert_eq!(sut.issuer(), PcCert::SpbSerpro);
        assert_eq!(sut.key_type(), Ok(AsymmetricKeyAlgo::RSA2048));
        assert!(sut.rsa_pub_key().is_ok());
    }
}
