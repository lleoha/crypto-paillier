use crypto_bigint::{U1024, U1536, U2048, U3072, U4096, U6144, U8192};

mod decryption;
mod encryption;

pub type PaillierDecryptionKey2048 =
    decryption::DecryptionKey<{ U1024::LIMBS }, { U2048::LIMBS }, { U4096::LIMBS }>;
pub type PaillierEncryptionKey2048 = encryption::EncryptionKey<{ U2048::LIMBS }, { U4096::LIMBS }>;

pub type PaillierDecryptionKey3072 =
    decryption::DecryptionKey<{ U1536::LIMBS }, { U3072::LIMBS }, { U6144::LIMBS }>;
pub type PaillierEncryptionKey3072 = encryption::EncryptionKey<{ U3072::LIMBS }, { U6144::LIMBS }>;

pub type PaillierDecryptionKey4096 =
    decryption::DecryptionKey<{ U2048::LIMBS }, { U4096::LIMBS }, { U8192::LIMBS }>;
pub type PaillierEncryptionKey4096 = encryption::EncryptionKey<{ U4096::LIMBS }, { U8192::LIMBS }>;
