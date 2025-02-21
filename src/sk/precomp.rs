use crypto_bigint::modular::{MontyParams, SafeGcdInverter};
use crypto_bigint::{Concat, Odd, PrecomputeInverter, Split, Uint};

#[derive(Debug, Copy, Clone)]
pub(crate) struct SecretPrecomputation<const H: usize, const S: usize> {
    pub(crate) pm1: Uint<H>,
    pub(crate) pp_monty_params: MontyParams<S>,
    pub(crate) hp: Uint<H>,
    pub(crate) qm1: Uint<H>,
    pub(crate) qq_monty_params: MontyParams<S>,
    pub(crate) hq: Uint<H>,
    pub(crate) q_inv: Uint<H>,
}

impl<const H: usize, const H_UNSAT: usize, const S: usize, const D: usize>
    SecretPrecomputation<H, S>
where
    Uint<H>: Concat<Output = Uint<S>>,
    Odd<Uint<H>>: PrecomputeInverter<Inverter = SafeGcdInverter<H, H_UNSAT>>,
    Uint<S>: Concat<Output = Uint<D>> + Split<Output = Uint<H>>,
    Uint<D>: Split<Output = Uint<S>>,
{
    pub fn new(p: &Odd<Uint<H>>, q: &Odd<Uint<H>>) -> Self {
        let n = p.widening_mul(q);

        let pm1 = p.wrapping_sub(&Uint::ONE);
        let pp = p.widening_square().to_odd().expect("p^2 is odd");
        let pp_monty_params = MontyParams::new(pp);
        let n_pp_reduced = n.rem(pp.as_nz_ref());
        let (hp_inv, _) = Uint::ONE
            .sub_mod(&n_pp_reduced, &pp)
            .wrapping_sub(&Uint::ONE)
            .wrapping_div(&p.resize().to_nz().expect("p is non zero"))
            .split();
        let hp = hp_inv.inv_odd_mod(p).expect("hp is invertible");

        let qm1 = q.wrapping_sub(&Uint::ONE);
        let qq = q.widening_square().to_odd().expect("q^2 is odd");
        let qq_monty_params = MontyParams::new(qq);
        let n_qq_reduced = n.rem(qq.as_nz_ref());
        let (hq_inv, _) = Uint::ONE
            .sub_mod(&n_qq_reduced, &qq)
            .wrapping_sub(&Uint::ONE)
            .wrapping_div(&q.resize().to_nz().expect("q is non zero"))
            .split();
        let hq = hq_inv.inv_odd_mod(q).expect("hq is invertible");

        let q_inv = q.inv_odd_mod(p).expect("q is invertible");

        SecretPrecomputation {
            pm1,
            pp_monty_params,
            hp,
            qm1,
            qq_monty_params,
            hq,
            q_inv,
        }
    }
}
