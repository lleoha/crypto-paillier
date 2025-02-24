use crypto_bigint::modular::{MontyForm, MontyParams};
use crypto_bigint::{Concat, NonZero, Odd, Split, Uint};

pub(crate) fn odd_widening_mul<const L: usize, const LL: usize>(x: &Odd<Uint<L>>, y: &Odd<Uint<L>>) -> Odd<Uint<LL>>
where
    Uint<L>: Concat<Output = Uint<LL>>,
    Uint<LL>: Split<Output = Uint<L>>,
{
    // product of two odd numbers is odd
    x.widening_mul(y).to_odd().unwrap()
}

pub(crate) fn odd_widening_square<const L: usize, const LL: usize>(x: &Odd<Uint<L>>) -> Odd<Uint<LL>>
where
    Uint<L>: Concat<Output = Uint<LL>>,
    Uint<LL>: Split<Output = Uint<L>>,
{
    // square of odd number is odd
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
    // x.mul_mod(y, m).to_nz().unwrap() //taking remainder is faster
    let z = x.widening_mul(y);
    z.rem(&m.resize().to_nz().unwrap()).resize().to_nz().unwrap()
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

pub(crate) fn wide_rem<const D: usize, const S: usize>(x: &Uint<D>, m: &NonZero<Uint<S>>) -> Uint<S>
where
    Uint<D>: Split<Output = Uint<S>>,
    Uint<S>: Concat<Output = Uint<D>>,
{
    x.div_rem(&m.resize().to_nz().unwrap()).1.resize()
}

pub(crate) fn wider_rem<const D: usize, const S: usize, const H: usize>(x: &Uint<D>, m: &NonZero<Uint<H>>) -> Uint<H>
where
    Uint<D>: Split<Output = Uint<S>>,
    Uint<S>: Split<Output = Uint<H>> + Concat<Output = Uint<D>>,
    Uint<H>: Concat<Output = Uint<S>>,
{
    x.div_rem(&m.resize().to_nz().unwrap()).1.resize()
}

pub(crate) fn wide_div<const D: usize, const S: usize>(n: &Uint<D>, d: &NonZero<Uint<S>>) -> Uint<S>
where
    Uint<D>: Split<Output = Uint<S>>,
    Uint<S>: Concat<Output = Uint<D>>,
{
    n.div_rem(&d.resize().to_nz().unwrap()).0.resize()
}
