use aes_gcm::aead::OsRng;
use rsa::{
    BigUint, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
    pkcs1::DecodeRsaPrivateKey,
    pkcs1v15::SigningKey,
    pkcs1v15::VerifyingKey,
    pkcs8::DecodePrivateKey,
    sha2::Sha256,
    signature::Verifier,
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
                .map_err(|error| format!("Falha ao ler chave no formato PKCS#8: {error}"))
        } else if data.starts_with("-----BEGIN RSA PRIVATE KEY----") {
            RsaPrivateKey::from_pkcs1_pem(data)
                .map_err(|error| format!("Falha ao ler chave no formato PKCS#1: {error}"))
        } else {
            Err("Formato da chave RSA não reconhecido".to_string())
        }
        .map(|key| Self { key })
    }

    /// Tamanho da chave.
    pub fn bits(&self) -> usize {
        let size = self.key.size() * 8;
        if size <= 512 {
            512
        } else if size <= 1024 {
            1024
        } else if size <= 2048 {
            2048
        } else if size <= 3072 {
            3072
        } else {
            4096
        }
    }

    /// Descriptografa dados.
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        self.key
            .decrypt(Pkcs1v15Encrypt, data)
            .map_err(|error| error.to_string())
    }

    /// Assina dados.
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        let key = SigningKey::<Sha256>::new(self.key.clone());
        key.sign_with_rng(&mut OsRng, data).to_bytes().into()
    }

    /// Chave pública.
    pub fn public_key(&self) -> RsaPublic {
        RsaPublic {
            key: self.key.to_public_key(),
        }
    }

    /// Valida se a chave pública é dessa chave privada.
    pub fn check_public_key(&self, public_key: &RsaPublic) -> bool {
        self.key.to_public_key() == public_key.key
    }
}

/// Manipula criptografia RSA com chave pública.
pub struct RsaPublic {
    key: RsaPublicKey,
}

impl RsaPublic {
    /// Inicia RSA com chave pública.
    pub fn new(n: BigUint, e: BigUint) -> Result<Self, String> {
        RsaPublicKey::new(n, e)
            .map_err(|error| error.to_string())
            .map(|key| Self { key })
    }

    /// Tamanho da chave.
    pub fn bits(&self) -> usize {
        let size = self.key.size() * 8;
        if size <= 512 {
            512
        } else if size <= 1024 {
            1024
        } else if size <= 2048 {
            2048
        } else if size <= 3072 {
            3072
        } else {
            4096
        }
    }

    /// Criptografa dados.
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        self.key
            .encrypt(&mut OsRng, Pkcs1v15Encrypt, data)
            .map_err(|error| error.to_string())
    }

    /// Verifica assinatura dos dados.
    pub fn verify(&self, data: &[u8], sign: &[u8]) -> Result<(), String> {
        let key = VerifyingKey::<Sha256>::new(self.key.clone());
        let signature = match sign.try_into() {
            Ok(signature) => signature,
            Err(error) => {
                return Err(format!("Formato da assinatura inválido: {error}"));
            }
        };
        key.verify(data, &signature)
            .map_err(|error| format!("Assinatura inválida: {error}"))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use rand::Rng;

    use super::*;

    #[test]
    fn private_key_in_pkcs1_format() {
        let mut rng = rand::rng();
        let data: Vec<_> = (0..64).map(|_| rng.random()).collect();

        let sut_src = RsaPrivate::load_pem(
            "-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCuElI0yoqwdhQbKYoBEg7UQTldXJ24DVCLASlAzH5ayqt0SmuC
Fzzt5QLi8lmhMv0gDmUxWgtu/ibCECzghdCD39AC0x4GDRLfbOEeSN00qXXovoPF
Hg2IvTlEgIiKBe5QihsHh9uh/kcoGaXDDKY8Av+zKx7gmFJDJTD6smUz3wIDAQAB
AoGAZI0ewXHyNUawDJStLDsjJ8bZfS2/yY6fZPxxuQWnQ4jpC47llUsZHg544WG/
FpfekgLev2hVTHMxLk6rrbJ+pIrlsI060M3eELO/YowURDukwM5DTC+ZGNAiLHMf
jS30vly2b20VniyC3aLS9Tb4NNJ5jbSRmJRW/tJTfbGVFEkCQQDTajqcTAwdP1DN
Qj2uUh7snG6n67laQ5zhZq5dTbrKpIgGG7+A8F8kczzv2LklbYDqk6G4TLUclzWu
JRSBWrKFAkEA0sgDzBapIS2wFafh+uTHHrMvj5q6QLvRtRTfjcUD32Hosbtfnfz9
eAt6AVaQJ8q3cGyNx3Znks51kzdQHZZkEwJBAMeQ91Ki1qylH/kiFmd/TYG9CReq
BIWYXXbIHsAkp7ayKVTazKNCRA18WoFt6xfRjmfghEAc6LncYufISNryaqECQDki
BgV3zvgzThtQmixLfr2PjEC8i+eoATu4ILBoypfuDgi+5TgJrxqu4a8jK4fdpsNO
aU+7hG+CjtQMliau8QkCQFccCL5GBnEDdnnVltXPFbhbxzgMugjCgGScoQvYJqM8
d+pIAFyYQt4TFVRkXzvce4w4CCpV/4nz2le1CIEo+gk=
-----END RSA PRIVATE KEY-----",
        )
        .unwrap();
        let sut_src_pub = sut_src.public_key();

        let sut_dst = RsaPrivate::load_pem(
            "-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA8pTKS0RqXoPwmqDoXKbDTzsnvgFs4iJJb4bWEv60oBrWCpIB
aRRGmod5oasb/AxjnAHoC4zSZsCWJrZW0FHNPPLRnh1tIfgftXdx9o6W77UevW6E
1emT51uGiJ8zC/OIY8jZovX0aodciNe0OVZugo37Bo3MoUs+ZmTeYeIn870gVYRW
qUF7XIJQYrWQX5nwpQSTAI01w6V3bSq14thA/48mFXe1huO9zOPDyaAv/5dnpQaC
eftakOn7V2DIHbE4ih7kb+rVPoJ6bdIuGzJWvya9jWxayA7ZxDK1Z4PQUM2iEMsM
G360Wkd6QZ7tMPUhlZK9870qVerSXstihCKL6QIDAQABAoIBADjKir2qS7jK7NZW
m2+tfwYalEhQbxxV6JlamN2jkcf14GxjGD9whsMAuoIV3BxbDirk611g35U8uype
/94PeJwvQNHik70jKNFEIIMXiNCft42jxSeLYpwEem+bzcibgC/UQtd6+3jBLfG/
hirySDb6ZG15XxHX2skADmweFTpjdPHXZQErY+3m78P24+DUDfiIPDP4mruEqblw
/HWD26rnloLn+ZHdUeO5kavCIsZm71ivfRdSELlXFotNeO/qf4zPtMV3gZ9vqdSI
qfWn2cDox/6xLQYmMXCAI5mmDc91kX33IpYnQoMDA49adV5LT4mxcwaavAko7Zb8
DeR6S30CgYEA+txBJM75CxJlRzknCFZQng7y1hXsWY6mo6a7m5oaq2HBrDRTx1B2
8O/B6rHhGHoyupVu1KItQ6XPvDkEr6WTRWpOzopPqauCAek+llqknFRU4WjP6KTu
MESSGA9KGNUwK9Y4qIvTvFqCEhY/cZdxhZ1Fl+42Y0jJu0EuuGTpBNMCgYEA940c
tGeIX9mKgzL0zBU77YO6mI5hJQTV5QJWpNiHGrv/m6RU5LiwC6Hs+6AiSvPNutUd
Ja3Fx5LkMEuxZxVEWeIBv1klY2uafJ5/OosuWWFqx+Ed7V5Bjixkbf7qa9t3AN+T
zEW0iPA2OOTx2XUpnMmVTLruZfIRCxqUyoyK5tMCgYAO/Fdb5o1UDv5D2fMt+VIJ
jyUMivS6iN4FirFMY1FSiZ1zNxEGKBVi4T+5UHT87FfZc5HSW/nOP7qAKPvRrld0
3xvkFLkbjqZOjOtzOej5ecQ0TvmUkT21XnNHwqoPf7TH+Z0a3HeCmfmJMRELLRvX
+oQsxkszdSav6/3pgAW3hwKBgGVokiy5CN2zARHz6uI7hJwszWC3WsZOb8zro1DO
PrJN90zsCbbUjZGGWM1PcRzhORLjQJhx0kaKPx4ls9u1k5V6hxq6yx0qNFP+ncH+
yBLnXFXbO2ZEqXgzaUTCG4fplJtv+1y/5U//j0bJSuW5ID3ROm7/WK+8dQzma7N5
1WDvAoGBAKOv2or9kjNx+PmF4xDWhnso0bACA+tdFWEkO4BmOnDy78p2hc5EM/r1
iAEOY6f3HJQT4QIxltWnmBBZ5LSlgH1HNsfNkBFoZXxrxs7tb/jAi3jZqlUe07qv
ek2TC+P0Au9UncIaheXYcdLmOKcMZtRQWM2fQSOfP56ISGDVJgMX
-----END RSA PRIVATE KEY-----",
        )
        .unwrap();
        let sut_dst_pub = sut_dst.public_key();

        assert_eq!(sut_src.bits(), 1024);
        assert_eq!(sut_src_pub.bits(), 1024);
        assert_eq!(sut_dst.bits(), 2048);
        assert_eq!(sut_dst_pub.bits(), 2048);

        let sign = sut_src.sign(&data);
        let encrypted = sut_dst_pub.encrypt(&data).unwrap();

        assert_ne!(sign, data);
        assert_ne!(encrypted, data);

        let plain = sut_dst.decrypt(&encrypted).unwrap();
        assert_eq!(plain, data);
        assert!(sut_src_pub.verify(&plain, &sign).is_ok());
    }

    #[test]
    fn private_key_in_pkcs8_format() {
        let mut rng = rand::rng();
        let data: Vec<_> = (0..64).map(|_| rng.random()).collect();

        let sut_src = RsaPrivate::load_pem(
            "-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAOiJ4DGpIfOEXL/t
g/T/Ocf7CqMoAPWHN/nb+ykileudrCuKWGkBU4nejeoyuFP0dQ/HrrWFy8UdlAIo
LwHyKY2YSV8UFN78Lfu9fmcs8IZtE4SDGNYr4gJljKicQ77hHfOfpUIXa/bExo9G
70QLdmGSWk5i9P6PRXKU4SO09rDdAgMBAAECgYAsVMym6wWL9TnxZQh5Focfdt6K
SEAWjta/DY8OQoeuSXrfOhqsuhIBAKqxcUXuy3XdskW+WWmFhKQI3TxI9K+y778J
R2RobJJ6jJH7kuxRGe+QLoiptMn6XOUkKr31IKeeAYjBG+J+Jqp/I0yKjqHV3zjZ
1pPSPksqOn7lzjG6yQJBAPj4Hv5JxK4txtm6VSakggL7IeMn2hlKLlfzAD5+gekI
VriI6K7fnOjs6KQVevz/1EbS4F1fm1lxVwmwxBeEifMCQQDvGvjlCLLvEsnUTkA7
Kbd9jAcIgRBzZL563Lg6UgwG3OItAaiG7B6pEChsRbqRDqh73sbWItUhoz/G1RCK
+T3vAkBS/bKnJUPwo8XDUj+MMA4+nCQBqokjIP0tyAzuyBDZ8zOlM84MbPHLGx25
hIeIymaibSzpMzN/ry5KRqg3BrFNAkBmWx6HNUUcEOfziZf3e7E//myYWF/JdiwQ
fmIjHTJm0bHE4HvbXkL1zqPvTZ5DMIoxlLl7u6ePYcoQfO86/t1jAkEAokITSRjR
hz7uDsRmpXmZDVTr5sUWbtLHAeZJayFpcU7J91prdMU+aP1TiUjYotBRLUZ7IWiL
UNu919pIE0/+MA==
-----END PRIVATE KEY-----",
        )
        .unwrap();
        let sut_src_pub = sut_src.public_key();

        let sut_dst = RsaPrivate::load_pem(
            "-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC5XqzjBC1jOdxc
twAx3ASZygxGdltvhJ5Slyu34FfT0GI3wWY450u+I4D6ngga1KOyzmCa54Wxd/aE
T768/EqhgDd/i9ocDAlhZTfbghSfraWGKDRiGiuGWLLShdvq/BLoZrpxNkM5+Mqr
A7iti7pPtrsjE7gBH7KQ9H0bZNKiPSu8afJsiKiXok1W7YkvZFk9uZBJkhoCdZ/p
n6Ek7qCL93uQvoxIbHQ9+k91tIw3TJPy/jHyC19BE4E3hGut8Q+78WCdt8CboSd3
HwHkvsCmfTp3hveH7XaNrNlv2mOH0KiyJTg6QZ1OEPl3k72wvolcBqcQ1r2Xuc6w
clNHBJq7AgMBAAECggEAGO+TcjZtpJtz+UTk0dA3DjkPzaq+QhIk+hc72lBjgCrY
C4gIqD71AW7lOtFnZbSVEMiSVkQux+DLWKEhl2qY34DP9mhpvrwfxupGyVCGVbSW
P6XI5il/EWN9KrS3ELU4Fes7yV7zTCkbmkW14iKZvX9nTSCp7/zDmJxK+BRoAUre
Tux+YbYyV3a/zW+53NWhtFfFHu5Kq1OCSr67VnT1+cIQufAWyfLOJarljpwV0+2z
7FoHNIUSNy+Q+rLA0aM7pLoXjaC1q+LZVUIWPddzrTZy0Fu9ZU/U6wc3ZDDzbOoR
2YQtjft8ldSpSPAqGYKncUgDGkYz7KNxQvB6r3SpAQKBgQDza8V3ahOSGE4LVm0Q
/oJOicU8C8Ir391hyh8KfAxze1DNOA+k8keg6J6gM3TeYOTvhe90HooJZI3pLun6
ThJjmBywky8oy/VSUwgG+n+0A7YFoZ1R7OgWUcC+Lu0p9I+gWOkUyZ9BdwAgqql5
2pOxeenwzZ7ShRHopH8hnGLfuQKBgQDC8vE4KGwkgOxwV2XGWGO12rTeCTZUiNyc
BmI2VbWtVaT7lnPgil28yT97aTpwgjU8hqutJHSYaMhCtkJMFAVQYXUWB/h32hwd
2WureATt1g5KeX9RBBpzbq1QWjzqp04T3BRw95K4Qlq+2h1Iqpaa57QMJiR0+r8w
qd3kFB4AEwKBgDyzuGeB/WVmSDgNkl81iJs7QgMqT36Pce6L79e2fYhizRCQFV6l
yHT47W23x0IZWZ3dgYwsfXHAMJ9gwppX08AgU6841P7QddnUuOC8oRHsBv06gzfF
406FjpIes6fNw+9RnLZBXUR+/3ol9ONdPY15gHw7WorXAlNIiieAjyuJAoGAP0F3
FcK//EQ88+LX6jjp+asCfv08PMe/1XyYx4qeDaU5iEz0QoqDCeu/BntJdBI71ezY
rbCjiISPXl4nOupQIxnMVR6296S09NaEgjnKV6XaMz4jGpWbQ5NI90agd39b7UO+
+jzKxbD6Iu1BDUAU6CSAnmSN9csa2F512jjQ1zMCgYBH24nVwqxLsPG3dIl79YI+
3C4hOaa23lCMQQfgEY7G6rMf6QnWUtRxeicBbRMVQxmt13KbBsx9Xn7vhNUnBirx
OZplITFtx1wmtr/kXAaSPAE3yso0mkf/9tIg90UK0gb7tMvHNZFTosXXY4Oei2TJ
x4t+WXdaScwveLoSinDIcQ==
-----END PRIVATE KEY-----",
        )
        .unwrap();
        let sut_dst_pub = sut_dst.public_key();

        assert_eq!(sut_src.bits(), 1024);
        assert_eq!(sut_src_pub.bits(), 1024);
        assert_eq!(sut_dst.bits(), 2048);
        assert_eq!(sut_dst_pub.bits(), 2048);

        let sign = sut_src.sign(&data);
        let encrypted = sut_dst_pub.encrypt(&data).unwrap();

        assert_ne!(sign, data);
        assert_ne!(encrypted, data);

        let plain = sut_dst.decrypt(&encrypted).unwrap();
        assert_eq!(plain, data);
        assert!(sut_src_pub.verify(&plain, &sign).is_ok());
    }

    #[test]
    fn unsuported_private_key_format() {
        assert!(
            RsaPrivate::load_pem(
                "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAIEAuCXB56raKJz4A9o/L9iD6sfuCr/eXZ/2q8+pq6ZyHi92OPENjcf6
ebaqRT7Q6z0YDt2oQwP7Nny2N+VKmmYDIRNyeL1VW+gy7NW2H8JMbxNv2aXqC416DE/3BP
Ed3i1bn1vItigwbVUpO2x9DJ0rqjvtg9xdjiKp1+tvSx94y+EAAAIIHcgd0h3IHdIAAAAH
c3NoLXJzYQAAAIEAuCXB56raKJz4A9o/L9iD6sfuCr/eXZ/2q8+pq6ZyHi92OPENjcf6eb
aqRT7Q6z0YDt2oQwP7Nny2N+VKmmYDIRNyeL1VW+gy7NW2H8JMbxNv2aXqC416DE/3BPEd
3i1bn1vItigwbVUpO2x9DJ0rqjvtg9xdjiKp1+tvSx94y+EAAAADAQABAAAAgFWIrDWYZX
bh2k2nzRvDPRsLvKTflED2sVQCxDPHv1AICajPRtVpYw2v7Az37YCmwwr8qFBghAo+CUGT
ToDDC4ZCcvp8B3RiGADuwCArgbFTevBl+j7FBDncWh8xoNK59bXQrS3sDmKtPEpm1qdwSQ
0aaNUMk8Va+5WuqmH7ljWxAAAAQEqFI1ja3p5TXFQH3cbYwK9s+7Y0K2nSu12qck08X/82
JXb6u8gt+3L+ouKNhJ/D5FOW6OU4kWmED8daHynSL+YAAABBAOcVgQQyJRSOqtu4TjzldH
VSaaOdCbFKNn6Jeq921W+OIxlZL14wlztm+yYq8gZC0jI4J/vbVwrmtjRgSMYYrF0AAABB
AMwAsD++b+hAJfdCAUqV/ZwrjNAdWgAFSqHr7M21KNOHmkMZncVUUpFJSfHcjPQirsAzH0
xj0rVLHpnzuyT0xVUAAAATdnNjb2RlQDk5NDc4Zjk3MzFkMw==
-----END OPENSSH PRIVATE KEY-----"
            )
            .is_err()
        )
    }

    #[test]
    fn public_key() {
        let mut rng = rand::rng();
        let data: Vec<_> = (0..64).map(|_| rng.random()).collect();

        let sut = RsaPrivate::load_pem(
            "-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBANSVXt1kxihQKF/S
u4QG917Hqr0HoUAvRoqBj3ov/pTgIUp5PRrMwIVZinHYzGm15w66iisk166zu/09
DMyfF1feWxFpNdPrDay75t5LdVQedm2i0wgQv0MNLt12mexbyze2HQ3ih+jRyKPU
+rWPAzWEQrUEeEw6HnnaLeyXywzFAgMBAAECgYA1WJ6LtEQ9zY+0LC++O/lLoZNp
CEcg0jxDeavFn9GlDnGMPMxms0cEr6mcVClHxcwL2CfgF8jAIH5mWDGkD7BNeRnT
zXUPaymG8WbhlTYMPuCKpy2RVcIm+CAIGTxt6ii8PrwA7b80dQHwVFAsmKak8cyi
cJ6D5eyuwFBzFIqXKQJBAPzsxkkT8lUz5NFsyluLqR1c3ULolGOqKbgfSq2gMqjm
FeDoGQ3QPErL+w95Rm71unvT4tzzvExRjKTfHbLGFBMCQQDXKwirX4pZeH2+nUXn
I6UDNGBHoRiv7GXZ0vSdIhX/IK6HB7IGbvoi8/vUCVfTUtlzMRUBvVbbVH8r6xno
YwbHAkEAoR/debSBTpIOlPOvPf6Mr633Lqan0Y4XobodgtppK3vYODzjqQ8dObEU
sVja69kTAcuL3KJRNHVHGckhTEAvjQJBALGV+P/ISN1zTwUltO4CQ00Ty2sTENcR
2zYeoHmYCmOZS7JyrYIV0ilLCcuFMpFdzc7+8YGQDcHUSWmsDqP4Jz0CQD234pR+
EJl3yDEDEwZftgqaxI/ZpwkxukcXsgvc248W+C+m7Yl2/ptli+0bPuOdrYGVof1i
8U0zcVHrbTi9tXE=
-----END PRIVATE KEY-----",
        )
        .unwrap();
        let sut_pub = RsaPublic::new(sut.key.n().clone(), sut.key.e().clone()).unwrap();

        assert!(sut.check_public_key(&sut_pub));

        let sign = sut.sign(&data);
        let encrypted = sut_pub.encrypt(&data).unwrap();

        assert_ne!(sign, data);
        assert_ne!(encrypted, data);

        let plain = sut.decrypt(&encrypted).unwrap();
        assert_eq!(plain, data);
        assert!(sut_pub.verify(&plain, &sign).is_ok());
    }

    #[test]
    fn incorrect_public_key() {
        let sut = RsaPrivate::load_pem(
            "-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBANSVXt1kxihQKF/S
u4QG917Hqr0HoUAvRoqBj3ov/pTgIUp5PRrMwIVZinHYzGm15w66iisk166zu/09
DMyfF1feWxFpNdPrDay75t5LdVQedm2i0wgQv0MNLt12mexbyze2HQ3ih+jRyKPU
+rWPAzWEQrUEeEw6HnnaLeyXywzFAgMBAAECgYA1WJ6LtEQ9zY+0LC++O/lLoZNp
CEcg0jxDeavFn9GlDnGMPMxms0cEr6mcVClHxcwL2CfgF8jAIH5mWDGkD7BNeRnT
zXUPaymG8WbhlTYMPuCKpy2RVcIm+CAIGTxt6ii8PrwA7b80dQHwVFAsmKak8cyi
cJ6D5eyuwFBzFIqXKQJBAPzsxkkT8lUz5NFsyluLqR1c3ULolGOqKbgfSq2gMqjm
FeDoGQ3QPErL+w95Rm71unvT4tzzvExRjKTfHbLGFBMCQQDXKwirX4pZeH2+nUXn
I6UDNGBHoRiv7GXZ0vSdIhX/IK6HB7IGbvoi8/vUCVfTUtlzMRUBvVbbVH8r6xno
YwbHAkEAoR/debSBTpIOlPOvPf6Mr633Lqan0Y4XobodgtppK3vYODzjqQ8dObEU
sVja69kTAcuL3KJRNHVHGckhTEAvjQJBALGV+P/ISN1zTwUltO4CQ00Ty2sTENcR
2zYeoHmYCmOZS7JyrYIV0ilLCcuFMpFdzc7+8YGQDcHUSWmsDqP4Jz0CQD234pR+
EJl3yDEDEwZftgqaxI/ZpwkxukcXsgvc248W+C+m7Yl2/ptli+0bPuOdrYGVof1i
8U0zcVHrbTi9tXE=
-----END PRIVATE KEY-----",
        )
        .unwrap();
        let sut_pub = RsaPublic::new(
            sut.key.n().clone() - BigUint::from_str("2").unwrap(),
            sut.key.e().clone(),
        )
        .unwrap();

        assert!(!sut.check_public_key(&sut_pub));
    }
}
