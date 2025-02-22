use crate::utils::{odd_widening_mul, odd_widening_square};
use crypto_bigint::modular::{MontyParams, SafeGcdInverter};
use crypto_bigint::{Concat, Odd, PrecomputeInverter, Split, Uint};

#[derive(Debug, Copy, Clone)]
pub(crate) struct SecretPrecomputation<const H: usize, const S: usize> {
    pub(crate) p_monty_params: MontyParams<H>,
    pub(crate) pm1: Uint<H>,
    pub(crate) pp_monty_params: MontyParams<S>,
    pub(crate) hp: Uint<H>,
    pub(crate) np_inv: Uint<H>,

    pub(crate) q_monty_params: MontyParams<H>,
    pub(crate) qm1: Uint<H>,
    pub(crate) qq_monty_params: MontyParams<S>,
    pub(crate) hq: Uint<H>,
    pub(crate) nq_inv: Uint<H>,

    pub(crate) q_inv: Uint<H>,
}

impl<const H: usize, const H_UNSAT: usize, const S: usize, const S_UNSAT: usize, const D: usize>
    SecretPrecomputation<H, S>
where
    Uint<H>: Concat<Output = Uint<S>>,
    Odd<Uint<H>>: PrecomputeInverter<Inverter = SafeGcdInverter<H, H_UNSAT>>,
    Uint<S>: Concat<Output = Uint<D>> + Split<Output = Uint<H>>,
    Odd<Uint<S>>: PrecomputeInverter<Inverter = SafeGcdInverter<S, S_UNSAT>>,
    Uint<D>: Split<Output = Uint<S>>,
{
    pub fn new(p: &Odd<Uint<H>>, q: &Odd<Uint<H>>) -> Self {
        let n = odd_widening_mul(p, q);

        let p_monty_params = MontyParams::new(p.to_owned());
        let pm1 = p.wrapping_sub(&Uint::ONE);
        let pp = odd_widening_square(p);
        let pp_monty_params = MontyParams::new(pp);
        let n_pp_reduced = n.rem(pp.as_nz_ref());
        let (hp_inv, _) = Uint::ONE
            .sub_mod(&n_pp_reduced, &pp)
            .wrapping_sub(&Uint::ONE)
            .wrapping_div(&p.resize().to_nz().expect("p is non zero"))
            .split();
        let hp = hp_inv.inv_odd_mod(p).expect("hp is invertible");

        let q_monty_params = MontyParams::new(q.to_owned());
        let qm1 = q.wrapping_sub(&Uint::ONE);
        let qq = odd_widening_square(q);
        let qq_monty_params = MontyParams::new(qq);
        let n_qq_reduced = n.rem(qq.as_nz_ref());
        let (hq_inv, _) = Uint::ONE
            .sub_mod(&n_qq_reduced, &qq)
            .wrapping_sub(&Uint::ONE)
            .wrapping_div(&q.resize().to_nz().expect("q is non zero"))
            .split();
        let hq = hq_inv.inv_odd_mod(q).expect("hq is invertible");
        let q_inv = q.inv_odd_mod(p).expect("q is invertible");

        let phi = pm1.widening_mul(&qm1);
        let n_inv = n.inv_mod(&phi).expect("1/n exists");
        let np_inv = n_inv.rem(&pm1.resize().to_nz().expect("p > 1")).resize();
        let nq_inv = n_inv.rem(&qm1.resize().to_nz().expect("q > 1")).resize();

        SecretPrecomputation {
            p_monty_params,
            pm1,
            pp_monty_params,
            hp,
            np_inv,
            q_monty_params,
            qm1,
            qq_monty_params,
            hq,
            nq_inv,
            q_inv,
        }
    }
}
