use crypto_bigint::{U1024, U1536, U2048, U3072, U4096, U6144, U8192};

mod pk;
mod sk;

pub type PaillierSecretKey2048 =
    sk::SecretKey<{ U1024::LIMBS }, { U2048::LIMBS }, { U4096::LIMBS }>;
pub type PaillierPublicKey2048 = pk::PublicKey<{ U2048::LIMBS }, { U4096::LIMBS }>;

pub type PaillierSecretKey3072 =
    sk::SecretKey<{ U1536::LIMBS }, { U3072::LIMBS }, { U6144::LIMBS }>;
pub type PaillierPublicKey3072 = pk::PublicKey<{ U3072::LIMBS }, { U6144::LIMBS }>;

pub type PaillierSecretKey4096 =
    sk::SecretKey<{ U2048::LIMBS }, { U4096::LIMBS }, { U8192::LIMBS }>;
pub type PaillierPublicKey4096 = pk::PublicKey<{ U4096::LIMBS }, { U8192::LIMBS }>;
