use crate::pk::PublicKey;
use crypto_bigint::modular::SafeGcdInverter;
use crypto_bigint::{Concat, NonZero, Odd, PrecomputeInverter, RandomMod, Split, Uint, Zero};
use rand_core::CryptoRng;
use subtle::ConstantTimeEq;

impl<const S: usize, const S_UNSAT: usize, const D: usize, const Q: usize> PublicKey<S, D>
where
    Uint<S>: Concat<Output = Uint<D>>,
    Odd<Uint<S>>: PrecomputeInverter<Inverter = SafeGcdInverter<S, S_UNSAT>>,
    Uint<D>: Split<Output = Uint<S>> + Concat<Output = Uint<Q>>,
    Uint<Q>: Split<Output = Uint<D>>,
{
    pub fn random_plaintext<R: CryptoRng + ?Sized>(&self, rng: &mut R) -> Uint<S> {
        Uint::random_mod(rng, self.n.as_nz_ref())
    }

    pub fn random_nonce<R: CryptoRng + ?Sized>(&self, rng: &mut R) -> NonZero<Uint<S>> {
        let mut result = Uint::ZERO;
        while (result.is_zero() | result.gcd(self.n.as_ref()).ct_ne(&Uint::ONE)).into() {
            result = Uint::random_mod(rng, self.n.as_nz_ref());
        }

        result.to_nz().expect("result is non zero")
    }
}

#[cfg(test)]
mod tests {
    use crate::EncryptionKey;
    use crate::{KeyGenerator, OpeningKey, PaillierSecretKey2048};
    use rand_chacha::ChaCha8Rng;
    use rand_chacha::rand_core::SeedableRng;

    #[test]
    fn should_generate_random_key() {
        let mut rng = ChaCha8Rng::from_os_rng();
        let (sk, pk) = PaillierSecretKey2048::random(&mut rng);

        let m = pk.random_plaintext(&mut rng);
        let (c, r) = pk.encrypt(&m, &mut rng);

        let (m2, r2) = sk.open(&c);
        assert_eq!(m, m2);
        assert_eq!(r, r2);
    }
}
