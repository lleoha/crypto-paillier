mod encrypt;
mod homomorphic;
mod precomp;
mod rand;

use crate::pk::precomp::PublicPrecomputation;
use crypto_bigint::{Concat, Odd, Split, Uint};

#[derive(Debug, Copy, Clone)]
pub struct PublicKey<const S: usize, const D: usize> {
    pub(crate) n: Odd<Uint<S>>,
    pub(crate) precomputation: PublicPrecomputation<S, D>,
}

impl<const S: usize, const D: usize, const Q: usize> PublicKey<S, D>
where
    Uint<S>: Concat<Output = Uint<D>>,
    Uint<D>: Split<Output = Uint<S>> + Concat<Output = Uint<Q>>,
    Uint<Q>: Split<Output = Uint<D>>,
{
    pub fn from_n_unchecked(n: Odd<Uint<S>>) -> Self {
        let precomputation = PublicPrecomputation::new(&n);

        PublicKey { n, precomputation }
    }
}
