use rand_core::CryptoRng;
use subtle::Choice;

pub trait Key<P> {
    type Ciphertext;
    type Nonce;

    fn plaintext_is_valid(&self, plaintext: &P) -> Choice;
    fn plaintext_eq(&self, plaintext_lhs: &P, plaintext_rhs: &P) -> Choice;

    fn ciphertext_is_valid(&self, ciphertext: &Self::Ciphertext) -> Choice;
    fn ciphertext_eq(&self, ciphertext_lhs: &Self::Ciphertext, ciphertext_rhs: &Self::Ciphertext) -> Choice;

    fn nonce_is_valid(&self, nonce: &Self::Nonce) -> Choice;
    fn nonce_eq(&self, nonce_lhs: &Self::Nonce, nonce_rhs: &Self::Nonce) -> Choice;
}

pub trait HomomorphicKey<P>: Key<P> {
    type Scalar;

    fn scalar_is_valid(&self, scalar: &Self::Scalar) -> Choice;
    fn scalar_eq(&self, scalar_lhs: &Self::Scalar, scalar_rhs: &Self::Scalar) -> Choice;

    fn ciphertext_add(&self, ciphertext_lhs: &Self::Ciphertext, ciphertext_rhs: &Self::Ciphertext) -> Self::Ciphertext;
    fn ciphertext_add_plain(&self, ciphertext: &Self::Ciphertext, plaintext: &P) -> Self::Ciphertext;
    fn ciphertext_sub(&self, ciphertext_lhs: &Self::Ciphertext, ciphertext_rhs: &Self::Ciphertext) -> Self::Ciphertext;
    fn ciphertext_sub_plain(&self, ciphertext: &Self::Ciphertext, plaintext: &P) -> Self::Ciphertext;
    fn ciphertext_neg(&self, ciphertext: &Self::Ciphertext) -> Self::Ciphertext;
    fn ciphertext_mul_scalar(&self, ciphertext: &Self::Ciphertext, scalar: &Self::Scalar) -> Self::Ciphertext;

    fn nonce_add(&self, nonce_lhs: &Self::Nonce, nonce_rhs: &Self::Nonce) -> Self::Nonce;
    fn nonce_sub(&self, nonce_lhs: &Self::Nonce, nonce_rhs: &Self::Nonce) -> Self::Nonce;
    fn nonce_neg(&self, nonce: &Self::Nonce) -> Self::Nonce;
    fn nonce_mul_scalar(&self, nonce: &Self::Nonce, scalar: &Self::Scalar) -> Self::Nonce;
}

pub trait EncryptionKey<P>: Key<P> {
    fn encrypt_with_nonce(&self, plaintext: &P, nonce: &Self::Nonce) -> Self::Ciphertext;
    fn encrypt<R: CryptoRng + ?Sized>(&self, plaintext: &P, rng: &mut R) -> (Self::Ciphertext, Self::Nonce);
}

pub trait DecryptionKey<P>: Key<P> {
    fn decrypt(&self, ciphertext: &Self::Ciphertext) -> P;
}

pub trait OpeningKey<P>: DecryptionKey<P> {
    fn open(&self, ciphertext: &Self::Ciphertext) -> (P, Self::Nonce);
}

pub trait KeyGenerator<P>: DecryptionKey<P> + Sized {
    type EncryptionKey: EncryptionKey<P> + Sized;

    fn random<R: CryptoRng + ?Sized>(rng: &mut R) -> (Self, Self::EncryptionKey);
}
