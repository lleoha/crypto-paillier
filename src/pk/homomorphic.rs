use crate::pk::PublicKey;
use crate::traits::HomomorphicEncryptionKey;
use crypto_bigint::modular::{MontyForm, SafeGcdInverter};
use crypto_bigint::{Concat, Odd, PrecomputeInverter, Split, Uint};

impl<const S: usize, const S_UNSAT: usize, const D: usize, const D_UNSAT: usize, const Q: usize>
    HomomorphicEncryptionKey<Uint<S>> for PublicKey<S, D>
where
    Uint<S>: Concat<Output = Uint<D>>,
    Odd<Uint<S>>: PrecomputeInverter<Inverter = SafeGcdInverter<S, S_UNSAT>>,
    Uint<D>: Split<Output = Uint<S>> + Concat<Output = Uint<Q>>,
    Odd<Uint<D>>: PrecomputeInverter<Inverter = SafeGcdInverter<D, D_UNSAT>>,
    Uint<Q>: Split<Output = Uint<D>>,
{
    type Scalar = Uint<S>;

    fn ciphertext_add(&self, cl: &Self::Ciphertext, cr: &Self::Ciphertext) -> Self::Ciphertext {
        cl.mul_mod(
            cr,
            self.precomputation.nn_monty_params.modulus().as_nz_ref(),
        )
        .to_nz()
        .expect("c is non zero")
    }

    fn ciphertext_add_plain(&self, c: &Self::Ciphertext, m: &Uint<S>) -> Self::Ciphertext {
        let g_to_m = self.n.widening_mul(m) + Uint::ONE;
        c.mul_mod(
            &g_to_m,
            self.precomputation.nn_monty_params.modulus().as_nz_ref(),
        )
        .to_nz()
        .expect("c is non zero")
    }

    fn ciphertext_sub(&self, cl: &Self::Ciphertext, cr: &Self::Ciphertext) -> Self::Ciphertext {
        let cr_inv = cr
            .inv_odd_mod(self.precomputation.nn_monty_params.modulus())
            .expect("c is invertible");
        cl.mul_mod(
            &cr_inv,
            self.precomputation.nn_monty_params.modulus().as_nz_ref(),
        )
        .to_nz()
        .expect("c is non zero")
    }

    fn ciphertext_sub_plain(&self, c: &Self::Ciphertext, m: &Uint<S>) -> Self::Ciphertext {
        let m_neg = self.n.wrapping_sub(m);
        let g_to_m = self.n.widening_mul(&m_neg) + Uint::ONE;
        c.mul_mod(
            &g_to_m,
            self.precomputation.nn_monty_params.modulus().as_nz_ref(),
        )
        .to_nz()
        .expect("c is non zero")
    }

    fn ciphertext_neg(&self, c: &Self::Ciphertext) -> Self::Ciphertext {
        c.inv_odd_mod(self.precomputation.nn_monty_params.modulus())
            .expect("c is invertible")
            .to_nz()
            .expect("c is non zero")
    }

    fn ciphertext_mul_scalar(&self, c: &Self::Ciphertext, s: &Self::Scalar) -> Self::Ciphertext {
        let c_monty_form = MontyForm::new(c, self.precomputation.nn_monty_params);
        c_monty_form
            .pow(s)
            .retrieve()
            .to_nz()
            .expect("c is non zero")
    }

    fn nonce_add(&self, rl: &Self::Nonce, rr: &Self::Nonce) -> Self::Nonce {
        rl.mul_mod(rr, self.n.as_nz_ref())
            .to_nz()
            .expect("r is non zero")
    }

    fn nonce_sub(&self, rl: &Self::Nonce, rr: &Self::Nonce) -> Self::Nonce {
        let rr_inv = rr.inv_odd_mod(&self.n).expect("r is invertible");
        rl.mul_mod(&rr_inv, self.n.as_nz_ref())
            .to_nz()
            .expect("r is non zero")
    }

    fn nonce_neg(&self, r: &Self::Nonce) -> Self::Nonce {
        r.inv_odd_mod(&self.n)
            .expect("c is invertible")
            .to_nz()
            .expect("r is non zero")
    }

    fn nonce_mul_scalar(&self, r: &Self::Nonce, s: &Self::Scalar) -> Self::Nonce {
        let r_monty_form = MontyForm::new(r, self.precomputation.n_monty_params);
        r_monty_form
            .pow(s)
            .retrieve()
            .to_nz()
            .expect("r is non zero")
    }
}

#[cfg(test)]
mod tests {
    use crate::HomomorphicEncryptionKey;
    use crate::{DecryptionKey, EncryptionKey, PaillierSecretKey2048};
    use crypto_bigint::rand_core::SeedableRng;
    use crypto_bigint::{RandomMod, Uint};
    use rand_chacha::ChaCha8Rng;

    #[test]
    fn should_homomorphic_add() {
        let mut rng = ChaCha8Rng::from_entropy();
        let sk = PaillierSecretKey2048::random(&mut rng);
        let pk = sk.as_public_key();

        let m1 = pk.random_plaintext(&mut rng);
        let m2 = pk.random_plaintext(&mut rng);
        let m = m1.add_mod(&m2, pk.n.as_nz_ref());

        let (c1, r1) = pk.encrypt(&m1, &mut rng);
        let (c2, r2) = pk.encrypt(&m2, &mut rng);
        let c = pk.ciphertext_add(&c1, &c2);
        let r = pk.nonce_add(&r1, &r2);

        let (m_actual, r_actual) = sk.open(&c);
        assert_eq!(m, m_actual);
        assert_eq!(r, r_actual);
    }

    #[test]
    fn should_homomorphic_add_plain() {
        let mut rng = ChaCha8Rng::from_entropy();
        let sk = PaillierSecretKey2048::random(&mut rng);
        let pk = sk.as_public_key();

        let m1 = pk.random_plaintext(&mut rng);
        let m2 = pk.random_plaintext(&mut rng);
        let m = m1.add_mod(&m2, pk.n.as_nz_ref());

        let (c1, r) = pk.encrypt(&m1, &mut rng);
        let c = pk.ciphertext_add_plain(&c1, &m2);

        let (m_actual, r_actual) = sk.open(&c);
        assert_eq!(m, m_actual);
        assert_eq!(r, r_actual);
    }

    #[test]
    fn should_homomorphic_sub() {
        let mut rng = ChaCha8Rng::from_entropy();
        let sk = PaillierSecretKey2048::random(&mut rng);
        let pk = sk.as_public_key();

        let m1 = pk.random_plaintext(&mut rng);
        let m2 = pk.random_plaintext(&mut rng);
        let m = m1.sub_mod(&m2, pk.n.as_nz_ref());

        let (c1, r1) = pk.encrypt(&m1, &mut rng);
        let (c2, r2) = pk.encrypt(&m2, &mut rng);
        let c = pk.ciphertext_sub(&c1, &c2);
        let r = pk.nonce_sub(&r1, &r2);

        let (m_actual, r_actual) = sk.open(&c);
        assert_eq!(m, m_actual);
        assert_eq!(r, r_actual);
    }

    #[test]
    fn should_homomorphic_sub_plain() {
        let mut rng = ChaCha8Rng::from_entropy();
        let sk = PaillierSecretKey2048::random(&mut rng);
        let pk = sk.as_public_key();

        let m1 = pk.random_plaintext(&mut rng);
        let m2 = pk.random_plaintext(&mut rng);
        let m = m1.sub_mod(&m2, pk.n.as_nz_ref());

        let (c1, r) = pk.encrypt(&m1, &mut rng);
        let c = pk.ciphertext_sub_plain(&c1, &m2);

        let (m_actual, r_actual) = sk.open(&c);
        assert_eq!(m, m_actual);
        assert_eq!(r, r_actual);
    }

    #[test]
    fn should_homomorphic_neg() {
        let mut rng = ChaCha8Rng::from_entropy();
        let sk = PaillierSecretKey2048::random(&mut rng);
        let pk = sk.as_public_key();

        let m1 = pk.random_plaintext(&mut rng);
        let m = m1.neg_mod(pk.n.as_nz_ref());

        let (c1, r1) = pk.encrypt(&m1, &mut rng);
        let c = pk.ciphertext_neg(&c1);
        let r = pk.nonce_neg(&r1);

        let (m_actual, r_actual) = sk.open(&c);
        assert_eq!(m, m_actual);
        assert_eq!(r, r_actual);
    }

    #[test]
    fn should_homomorphic_mul_scalar() {
        let mut rng = ChaCha8Rng::from_entropy();
        let sk = PaillierSecretKey2048::random(&mut rng);
        let pk = sk.as_public_key();

        let m1 = pk.random_plaintext(&mut rng);
        let s = Uint::random_mod(&mut rng, pk.n.as_nz_ref());
        let m = m1.mul_mod(&s, pk.n.as_nz_ref());

        let (c1, r1) = pk.encrypt(&m1, &mut rng);
        let c = pk.ciphertext_mul_scalar(&c1, &s);
        let r = pk.nonce_mul_scalar(&r1, &s);

        let (m_actual, r_actual) = sk.open(&c);
        assert_eq!(m, m_actual);
        assert_eq!(r, r_actual);
    }
}
