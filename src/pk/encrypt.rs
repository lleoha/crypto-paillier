use crate::pk::PublicKey;
use crate::traits::EncryptionKey;
use crypto_bigint::modular::{MontyForm, SafeGcdInverter};
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

    fn encrypt_with_nonce(&self, m: &Uint<S>, r: &NonZero<Uint<S>>) -> NonZero<Uint<D>> {
        // TODO(mkk): check r < n, check gcd(r, n) == 1

        let g_to_m = self.n.widening_mul(m) + Uint::ONE;
        let r_monty_form = MontyForm::new(&r.resize(), self.precomputation.nn_monty_params);
        let r_to_n = r_monty_form.pow(&self.n).retrieve();

        g_to_m
            .mul_mod(
                &r_to_n,
                self.precomputation.nn_monty_params.modulus().as_nz_ref(),
            )
            .to_nz()
            .expect("c is non zero")
    }

    fn encrypt<R: RngCore + ?Sized>(
        &self,
        m: &Uint<S>,
        rng: &mut R,
    ) -> (NonZero<Uint<D>>, NonZero<Uint<S>>) {
        let r = self.random_nonce(rng);
        let c = self.encrypt_with_nonce(m, &r);
        (c, r)
    }
}
