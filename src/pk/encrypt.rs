use crate::pk::PublicKey;
use crate::traits::EncryptionKey;
use crate::utils::{nz_mul_mod, nz_pow_mod, nz_resize};
use crypto_bigint::modular::SafeGcdInverter;
use crypto_bigint::rand_core::RngCore;
use crypto_bigint::{Concat, NonZero, Odd, PrecomputeInverter, Split, Uint};

impl<const S: usize, const S_UNSAT: usize, const D: usize, const Q: usize> EncryptionKey<Uint<S>>
    for PublicKey<S, D>
where
    Uint<S>: Concat<Output = Uint<D>>,
    Odd<Uint<S>>: PrecomputeInverter<Inverter = SafeGcdInverter<S, S_UNSAT>>,
    Uint<D>: Split<Output = Uint<S>> + Concat<Output = Uint<Q>>,
    Uint<Q>: Split<Output = Uint<D>>,
{
    type Ciphertext = NonZero<Uint<D>>;
    type Nonce = NonZero<Uint<S>>;

    fn encrypt_with_nonce(&self, m: &Uint<S>, r: &Self::Nonce) -> Self::Ciphertext {
        // TODO(mkk): check r < n, check gcd(r, n) == 1

        let g_to_m = NonZero::new(self.n.widening_mul(m) + Uint::ONE).unwrap();
        let r_to_n = nz_pow_mod(
            &nz_resize(r),
            self.n.as_nz_ref(),
            &self.precomputation.nn_monty_params,
        );

        nz_mul_mod(
            &g_to_m,
            &r_to_n,
            self.precomputation.nn_monty_params.modulus().as_nz_ref(),
        )
    }

    fn encrypt<R: RngCore + ?Sized>(
        &self,
        m: &Uint<S>,
        rng: &mut R,
    ) -> (Self::Ciphertext, Self::Nonce) {
        let r = self.random_nonce(rng);
        let c = self.encrypt_with_nonce(m, &r);
        (c, r)
    }
}
