use crypto_bigint::modular::MontyParams;
use crypto_bigint::{Concat, Odd, Split, Uint};

#[derive(Debug, Copy, Clone)]
pub(crate) struct PublicPrecomputation<const S: usize, const D: usize> {
    pub(crate) n_monty_params: MontyParams<S>,
    pub(crate) nn_monty_params: MontyParams<D>,
}

impl<const S: usize, const D: usize, const Q: usize> PublicPrecomputation<S, D>
where
    Uint<S>: Concat<Output = Uint<D>>,
    Uint<D>: Concat<Output = Uint<Q>> + Split<Output = Uint<S>>,
    Uint<Q>: Split<Output = Uint<D>>,
{
    pub(crate) fn new(n: &Odd<Uint<S>>) -> Self {
        let n_monty_params = MontyParams::new(n.to_owned());
        let nn = n.widening_square().to_odd().expect("n^2 is odd");
        let nn_monty_params = MontyParams::new(nn);

        PublicPrecomputation {
            n_monty_params,
            nn_monty_params,
        }
    }
}
