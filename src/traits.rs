use crypto_bigint::rand_core::RngCore;

pub trait EncryptionKey<M> {
    type Ciphertext;
    type Nonce;

    fn encrypt_with_nonce(&self, message: &M, nonce: &Self::Nonce) -> Self::Ciphertext;
    fn encrypt<R: RngCore + ?Sized>(
        &self,
        message: &M,
        rng: &mut R,
    ) -> (Self::Ciphertext, Self::Nonce);
}

pub trait HomomorphicEncryptionKey<M>: EncryptionKey<M> {
    type Scalar;

    fn ciphertext_add(&self, cl: &Self::Ciphertext, cr: &Self::Ciphertext) -> Self::Ciphertext;
    fn ciphertext_add_plain(&self, c: &Self::Ciphertext, m: &M) -> Self::Ciphertext;
    fn ciphertext_sub(&self, cl: &Self::Ciphertext, cr: &Self::Ciphertext) -> Self::Ciphertext;
    fn ciphertext_sub_plain(&self, c: &Self::Ciphertext, m: &M) -> Self::Ciphertext;
    fn ciphertext_neg(&self, c: &Self::Ciphertext) -> Self::Ciphertext;
    fn ciphertext_mul_scalar(&self, c: &Self::Ciphertext, s: &Self::Scalar) -> Self::Ciphertext;

    fn nonce_add(&self, rl: &Self::Nonce, rr: &Self::Nonce) -> Self::Nonce;
    fn nonce_sub(&self, rl: &Self::Nonce, rr: &Self::Nonce) -> Self::Nonce;
    fn nonce_neg(&self, r: &Self::Nonce) -> Self::Nonce;
    fn nonce_mul_scalar(&self, r: &Self::Nonce, s: &Self::Scalar) -> Self::Nonce;
}

pub trait DecryptionKey<M> {
    type Ciphertext;
    type Nonce;

    fn decrypt(&self, ciphertext: &Self::Ciphertext) -> M;
    fn open(&self, ciphertext: &Self::Ciphertext) -> (M, Self::Nonce);
}
