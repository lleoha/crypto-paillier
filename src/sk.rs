mod dec;
mod precomp;

use crate::pk::PublicKey;
use crate::sk::precomp::SecretPrecomputation;
use crypto_bigint::modular::SafeGcdInverter;
use crypto_bigint::rand_core::CryptoRngCore;
use crypto_bigint::{Concat, Odd, PrecomputeInverter, Split, Uint};
use crypto_primes::RandomPrimeWithRng;

#[derive(Debug, Copy, Clone)]
pub struct SecretKey<const H: usize, const S: usize, const D: usize> {
    pub(crate) pk: PublicKey<S, D>,
    pub(crate) p: Odd<Uint<H>>,
    pub(crate) q: Odd<Uint<H>>,
    pub(crate) precomputation: SecretPrecomputation<H, S>,
}

impl<
    const H: usize,
    const H_UNSAT: usize,
    const S: usize,
    const S_UNSAT: usize,
    const D: usize,
    const Q: usize,
> SecretKey<H, S, D>
where
    Uint<H>: Concat<Output = Uint<S>>,
    Odd<Uint<H>>: PrecomputeInverter<Inverter = SafeGcdInverter<H, H_UNSAT>>,
    Uint<S>: Split<Output = Uint<H>> + Concat<Output = Uint<D>>,
    Odd<Uint<S>>: PrecomputeInverter<Inverter = SafeGcdInverter<S, S_UNSAT>>,
    Uint<D>: Split<Output = Uint<S>> + Concat<Output = Uint<Q>>,
    Uint<Q>: Split<Output = Uint<D>>,
{
    pub fn random<R: CryptoRngCore + ?Sized>(rng: &mut R) -> Self {
        let mut p = Uint::ZERO;
        let mut q = Uint::ZERO;
        while p == q {
            p = Uint::generate_prime_with_rng(rng, Uint::<H>::BITS);
            q = Uint::generate_prime_with_rng(rng, Uint::<H>::BITS);
        }

        Self::from_primes_unchecked(p.to_odd().expect("p is odd"), q.to_odd().expect("q is odd"))
    }

    pub fn from_primes<R: CryptoRngCore + ?Sized>(
        p: Odd<Uint<H>>,
        q: Odd<Uint<H>>,
        rng: &mut R,
    ) -> Self {
        if p == q
            || p.bits() != Uint::<H>::BITS
            || q.bits() != Uint::<H>::BITS
            || !p.as_ref().is_prime_with_rng(rng)
            || !q.as_ref().is_prime_with_rng(rng)
        {
            panic!("p and q must be prime and have the same length");
        }

        Self::from_primes_unchecked(p, q)
    }

    pub fn from_primes_unchecked(p: Odd<Uint<H>>, q: Odd<Uint<H>>) -> Self {
        let n = p.widening_mul(&q).to_odd().expect("n is odd");
        let pk = PublicKey::from_n_unchecked(n);
        let precomputation = SecretPrecomputation::new(&p, &q);

        SecretKey {
            pk,
            p,
            q,
            precomputation,
        }
    }

    pub fn as_public_key(&self) -> PublicKey<S, D> {
        self.pk.to_owned()
    }
}
