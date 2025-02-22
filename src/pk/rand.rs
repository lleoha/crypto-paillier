use crate::pk::PublicKey;
use crypto_bigint::modular::SafeGcdInverter;
use crypto_bigint::rand_core::RngCore;
use crypto_bigint::subtle::ConstantTimeEq;
use crypto_bigint::{Concat, NonZero, Odd, PrecomputeInverter, RandomMod, Split, Uint, Zero};

impl<const S: usize, const S_UNSAT: usize, const D: usize, const Q: usize> PublicKey<S, D>
where
    Uint<S>: Concat<Output = Uint<D>>,
    Odd<Uint<S>>: PrecomputeInverter<Inverter = SafeGcdInverter<S, S_UNSAT>>,
    Uint<D>: Split<Output = Uint<S>> + Concat<Output = Uint<Q>>,
    Uint<Q>: Split<Output = Uint<D>>,
{
    pub fn random_plaintext<R: RngCore + ?Sized>(&self, rng: &mut R) -> Uint<S> {
        Uint::random_mod(rng, self.n.as_nz_ref())
    }

    pub fn random_nonce<R: RngCore + ?Sized>(&self, rng: &mut R) -> NonZero<Uint<S>> {
        let mut result = Uint::ZERO;
        while (result.is_zero() | result.gcd(self.n.as_ref()).ct_ne(&Uint::ONE)).into() {
            result = Uint::random_mod(rng, self.n.as_nz_ref());
        }

        result.to_nz().expect("result is non zero")
    }
}

#[cfg(test)]
mod tests {
    use crate::PaillierSecretKey2048;
    use crate::{DecryptionKey, EncryptionKey};
    use rand_chacha::ChaCha8Rng;
    use rand_chacha::rand_core::SeedableRng;

    #[test]
    fn should_generate_random_key() {
        let mut rng = ChaCha8Rng::from_entropy();

        let sk = PaillierSecretKey2048::random(&mut rng);
        let pk = sk.as_public_key();

        let m = pk.random_plaintext(&mut rng);
        let (c, r) = pk.encrypt(&m, &mut rng);

        let (m2, r2) = sk.open(&c);
        assert_eq!(m, m2);
        assert_eq!(r, r2);
    }
}
