#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SignatureScheme {
    /* RSASSA-PKCS1-v1_5 algorithms */
    RsaPkcs1Sha256 = 0x0401,
    RsaPkcs1Sha384 = 0x0501,
    RsaPkcs1Sha512 = 0x0601,

    /* ECDSA algorithms */
    EcdsaSecp256r1Sha256 = 0x0403,
    EcdsaSecp384r1Sha384 = 0x0503,
    EcdsaSecp521r1Sha512 = 0x0603,

    /* RSASSA-PSS algorithms with public key OID rsaEncryption */
    RsaPssRsaeSha256 = 0x0804,
    RsaPssRsaeSha384 = 0x0805,
    RsaPssRsaeSha512 = 0x0806,

    /* EdDSA algorithms */
    Ed25519 = 0x0807,
    Ed448 = 0x0808,

    /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
    RsaPssPssSha256 = 0x0809,
    RsaPssPssSha384 = 0x080a,
    RsaPssPssSha512 = 0x080b,

    /* Legacy algorithms */
    RsaPkcs1Sha1 = 0x0201,
    EcdsaSha1 = 0x0203,
    /* Reserved Code Points */
    //private_use(0xFE00..0xFFFF),
    //(0xFFFF)
}

impl SignatureScheme {
    pub fn of(num: u16) -> Option<Self> {
        match num {
            0x0401 => Some(Self::RsaPkcs1Sha256),
            0x0501 => Some(Self::RsaPkcs1Sha384),
            0x0601 => Some(Self::RsaPkcs1Sha512),

            0x0403 => Some(Self::EcdsaSecp256r1Sha256),
            0x0503 => Some(Self::EcdsaSecp384r1Sha384),
            0x0603 => Some(Self::EcdsaSecp521r1Sha512),

            0x0804 => Some(Self::RsaPssRsaeSha256),
            0x0805 => Some(Self::RsaPssRsaeSha384),
            0x0806 => Some(Self::RsaPssRsaeSha512),

            0x0807 => Some(Self::Ed25519),
            0x0808 => Some(Self::Ed448),

            0x0809 => Some(Self::RsaPssPssSha256),
            0x080a => Some(Self::RsaPssPssSha384),
            0x080b => Some(Self::RsaPssPssSha512),

            0x0201 => Some(Self::RsaPkcs1Sha1),
            0x0203 => Some(Self::EcdsaSha1),
            _ => None,
        }
    }
}
