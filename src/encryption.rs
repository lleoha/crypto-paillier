use crypto_bigint::modular::{MontyForm, MontyParams};
use crypto_bigint::{Concat, NonZero, Odd, Split, Uint};

#[derive(Debug, Copy, Clone)]
pub struct PublicPrecomputation<const D: usize> {
    pub(crate) nn_monty_params: MontyParams<D>,
}

impl<const S: usize, const D: usize, const Q: usize> PublicPrecomputation<D>
where
    Uint<S>: Concat<Output = Uint<D>>,
    Uint<D>: Concat<Output = Uint<Q>> + Split<Output = Uint<S>>,
    Uint<Q>: Split<Output = Uint<D>>,
{
    pub(crate) fn new(n: Odd<Uint<S>>) -> Self {
        let nn = n.widening_square().to_odd().expect("nn is odd");
        let nn_monty_params = MontyParams::new(nn);

        PublicPrecomputation { nn_monty_params }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct EncryptionKey<const S: usize, const D: usize> {
    pub(crate) n: Odd<Uint<S>>,
    pub(crate) precomputation: PublicPrecomputation<D>,
}

impl<const S: usize, const D: usize, const Q: usize> EncryptionKey<S, D>
where
    Uint<S>: Concat<Output = Uint<D>>,
    Uint<D>: Split<Output = Uint<S>> + Concat<Output = Uint<Q>>,
    Uint<Q>: Split<Output = Uint<D>>,
{
    pub fn new(n: Odd<Uint<S>>) -> Self {
        let precomputation = PublicPrecomputation::new(n);

        EncryptionKey { n, precomputation }
    }

    pub fn encrypt_with_nonce(&self, m: &Uint<S>, r: &NonZero<Uint<S>>) -> Uint<D> {
        // TODO(mkk): check r < n, check gcd(r, n) == 1

        let g_to_m = self.n.widening_mul(m) + Uint::ONE;
        let r_monty_form = MontyForm::new(&r.resize(), self.precomputation.nn_monty_params);
        let r_to_n = r_monty_form.pow(&self.n).retrieve();
        let c = g_to_m.resize().mul_mod(
            &r_to_n,
            self.precomputation.nn_monty_params.modulus().as_nz_ref(),
        );

        c
    }
}
