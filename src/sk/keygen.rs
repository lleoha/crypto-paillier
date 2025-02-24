use crate::pk::PublicKey;
use crate::sk::SecretKey;
use crate::traits::KeyGenerator;
use crypto_bigint::modular::SafeGcdInverter;
use crypto_bigint::{Concat, Odd, PrecomputeInverter, Split, Uint};
use crypto_primes::RandomPrimeWithRng;
use rand_core::CryptoRng;

impl<
    const H: usize,
    const H_UNSAT: usize,
    const S: usize,
    const S_UNSAT: usize,
    const D: usize,
    const D_UNSAT: usize,
    const Q: usize,
> KeyGenerator<Uint<S>> for SecretKey<H, S, D>
where
    Uint<H>: Concat<Output = Uint<S>>,
    Odd<Uint<H>>: PrecomputeInverter<Inverter = SafeGcdInverter<H, H_UNSAT>>,
    Uint<S>: Split<Output = Uint<H>> + Concat<Output = Uint<D>>,
    Odd<Uint<S>>: PrecomputeInverter<Inverter = SafeGcdInverter<S, S_UNSAT>>,
    Uint<D>: Split<Output = Uint<S>> + Concat<Output = Uint<Q>>,
    Odd<Uint<D>>: PrecomputeInverter<Inverter = SafeGcdInverter<D, D_UNSAT>>,
    Uint<Q>: Split<Output = Uint<D>>,
{
    type EncryptionKey = PublicKey<S, D>;

    fn random<R: CryptoRng + ?Sized>(rng: &mut R) -> (Self, Self::EncryptionKey) {
        let mut p = Uint::ZERO;
        let mut q = Uint::ZERO;
        while p == q {
            p = Uint::generate_prime_with_rng(rng, Uint::<H>::BITS);
            q = Uint::generate_prime_with_rng(rng, Uint::<H>::BITS);
        }

        let sk = Self::from_primes_unchecked(p.to_odd().unwrap(), q.to_odd().unwrap());
        let pk = sk.pk;
        (sk, pk)
    }
}
