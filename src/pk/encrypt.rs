use crate::pk::PublicKey;
use crate::traits::{EncryptionKey, Key};
use crate::utils::{nz_mul_mod, nz_pow_mod, nz_resize};
use crypto_bigint::modular::SafeGcdInverter;
use crypto_bigint::{Concat, NonZero, Odd, PrecomputeInverter, Split, Uint};
use rand_core::CryptoRng;
use subtle::{Choice, ConstantTimeEq, ConstantTimeLess};

impl<const S: usize, const S_UNSAT: usize, const D: usize, const D_UNSAT: usize> Key<Uint<S>> for PublicKey<S, D>
where
    Uint<S>: Concat<Output = Uint<D>>,
    Odd<Uint<S>>: PrecomputeInverter<Inverter = SafeGcdInverter<S, S_UNSAT>>,
    Uint<D>: Split<Output = Uint<S>>,
    Odd<Uint<D>>: PrecomputeInverter<Inverter = SafeGcdInverter<D, D_UNSAT>>,
{
    type Ciphertext = NonZero<Uint<D>>;
    type Nonce = NonZero<Uint<S>>;

    fn plaintext_is_valid(&self, m: &Uint<S>) -> Choice {
        m.ct_lt(&self.n)
    }

    fn plaintext_eq(&self, ml: &Uint<S>, mr: &Uint<S>) -> Choice {
        self.plaintext_is_valid(ml) & self.plaintext_is_valid(mr) & ml.ct_eq(mr)
    }

    fn ciphertext_is_valid(&self, c: &Self::Ciphertext) -> Choice {
        c.ct_lt(self.precomputation.nn_monty_params.modulus())
            & c.gcd(self.precomputation.nn_monty_params.modulus()).ct_eq(&Uint::ONE)
    }

    fn ciphertext_eq(&self, cl: &Self::Ciphertext, cr: &Self::Ciphertext) -> Choice {
        self.ciphertext_is_valid(cl) & self.ciphertext_is_valid(cr) & cl.ct_eq(cr)
    }

    fn nonce_is_valid(&self, r: &Self::Nonce) -> Choice {
        r.ct_lt(&self.n) & r.gcd(&self.n).ct_eq(&Uint::ONE)
    }

    fn nonce_eq(&self, rl: &Self::Nonce, rr: &Self::Nonce) -> Choice {
        self.nonce_is_valid(rr) & self.nonce_is_valid(rl) & rl.ct_eq(rr)
    }
}

impl<const S: usize, const S_UNSAT: usize, const D: usize, const D_UNSAT: usize, const Q: usize> EncryptionKey<Uint<S>>
    for PublicKey<S, D>
where
    Uint<S>: Concat<Output = Uint<D>>,
    Odd<Uint<S>>: PrecomputeInverter<Inverter = SafeGcdInverter<S, S_UNSAT>>,
    Uint<D>: Split<Output = Uint<S>> + Concat<Output = Uint<Q>>,
    Odd<Uint<D>>: PrecomputeInverter<Inverter = SafeGcdInverter<D, D_UNSAT>>,
    Uint<Q>: Split<Output = Uint<D>>,
{
    fn encrypt_with_nonce(&self, m: &Uint<S>, r: &Self::Nonce) -> Self::Ciphertext {
        let g_to_m = NonZero::new(self.n.widening_mul(m) + Uint::ONE).unwrap();
        let r_to_n = nz_pow_mod(&nz_resize(r), self.n.as_nz_ref(), &self.precomputation.nn_monty_params);

        nz_mul_mod(
            &g_to_m,
            &r_to_n,
            self.precomputation.nn_monty_params.modulus().as_nz_ref(),
        )
    }

    fn encrypt<R: CryptoRng + ?Sized>(&self, m: &Uint<S>, rng: &mut R) -> (Self::Ciphertext, Self::Nonce) {
        let r = self.random_nonce(rng);
        let c = self.encrypt_with_nonce(m, &r);
        (c, r)
    }
}
