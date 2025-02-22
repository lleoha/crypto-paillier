use crypto_bigint::modular::{MontyForm, MontyParams};
use crypto_bigint::{Concat, NonZero, Odd, Split, Uint};

pub(crate) fn odd_widening_mul<const L: usize, const LL: usize>(
    x: &Odd<Uint<L>>,
    y: &Odd<Uint<L>>,
) -> Odd<Uint<LL>>
where
    Uint<L>: Concat<Output = Uint<LL>>,
    Uint<LL>: Split<Output = Uint<L>>,
{
    x.widening_mul(y).to_odd().unwrap()
}

pub(crate) fn odd_widening_square<const L: usize, const LL: usize>(
    x: &Odd<Uint<L>>,
) -> Odd<Uint<LL>>
where
    Uint<L>: Concat<Output = Uint<LL>>,
    Uint<LL>: Split<Output = Uint<L>>,
{
    x.widening_square().to_odd().unwrap()
}

pub(crate) fn nz_mul_mod<const L: usize, const LL: usize>(
    x: &NonZero<Uint<L>>,
    y: &NonZero<Uint<L>>,
    m: &NonZero<Uint<L>>,
) -> NonZero<Uint<L>>
where
    Uint<L>: Concat<Output = Uint<LL>>,
    Uint<LL>: Split<Output = Uint<L>>,
{
    // x.mul_mod(y, m).to_nz().unwrap()
    // taking remainder is much faster
    let z = x.widening_mul(y);
    z.rem(&m.resize().to_nz().unwrap())
        .resize()
        .to_nz()
        .unwrap()
}

pub(crate) fn nz_pow_mod<const L: usize, const R: usize>(
    b: &NonZero<Uint<L>>,
    e: &Uint<R>,
    m: &MontyParams<L>,
) -> NonZero<Uint<L>> {
    let b_monty_form = MontyForm::new(b.as_ref(), m.to_owned());
    let z = b_monty_form.pow(e);
    z.retrieve().to_nz().unwrap()
}

pub(crate) fn nz_resize<const L: usize, const R: usize>(x: &NonZero<Uint<L>>) -> NonZero<Uint<R>> {
    x.resize().to_nz().unwrap()
}
