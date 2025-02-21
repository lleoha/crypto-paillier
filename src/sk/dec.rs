use crate::sk::SecretKey;
use crypto_bigint::modular::{MontyForm, SafeGcdInverter};
use crypto_bigint::{Concat, Odd, PrecomputeInverter, Split, Uint};

impl<const H: usize, const UNSAT_H: usize, const S: usize, const D: usize, const Q: usize>
    SecretKey<H, S, D>
where
    Uint<H>: Concat<Output = Uint<S>>,
    Odd<Uint<H>>: PrecomputeInverter<Inverter = SafeGcdInverter<H, UNSAT_H>>,
    Uint<S>: Split<Output = Uint<H>> + Concat<Output = Uint<D>>,
    Uint<D>: Split<Output = Uint<S>> + Concat<Output = Uint<Q>>,
    Uint<Q>: Split<Output = Uint<D>>,
{
    pub fn decrypt(&self, c: &Uint<D>) -> Uint<S> {
        let lp = self.fermat_quotient_p(c);
        let mp = lp.mul_mod(&self.precomputation.hp, self.p.as_nz_ref());
        let lq = self.fermat_quotient_q(c);
        let mq = lq.mul_mod(&self.precomputation.hq, self.q.as_nz_ref());

        self.crt(&mp, &mq)
    }

    fn fermat_quotient_p(&self, x: &Uint<D>) -> Uint<H> {
        let x_reduced = x
            .rem(
                &self
                    .precomputation
                    .pp_monty_params
                    .modulus()
                    .resize()
                    .to_nz()
                    .expect("p^2 is non zero"),
            )
            .resize();
        let x_monty_form = MontyForm::new(&x_reduced, self.precomputation.pp_monty_params);
        let x_to_pm1 = x_monty_form.pow(&self.precomputation.pm1);
        let nom = x_to_pm1.retrieve() - Uint::ONE;

        nom.wrapping_div(&self.p.resize().to_nz().expect("p is non zero"))
            .resize()
    }

    fn fermat_quotient_q(&self, x: &Uint<D>) -> Uint<H> {
        let x_reduced = x
            .rem(
                &self
                    .precomputation
                    .qq_monty_params
                    .modulus()
                    .resize()
                    .to_nz()
                    .expect("q^2 is non zero"),
            )
            .resize();
        let x_monty_form = MontyForm::new(&x_reduced, self.precomputation.qq_monty_params);
        let x_to_qm1 = x_monty_form.pow(&self.precomputation.qm1);
        let nom = x_to_qm1.retrieve() - Uint::ONE;

        nom.wrapping_div(&self.q.resize().to_nz().expect("q is non zero"))
            .resize()
    }

    fn crt(&self, mp: &Uint<H>, mq: &Uint<H>) -> Uint<S> {
        let mp_reduced = mp.rem(self.p.as_nz_ref());
        let mq_reduced = mq.rem(self.p.as_nz_ref());
        let h = mp_reduced
            .sub_mod(&mq_reduced, self.p.as_ref())
            .mul_mod(&self.precomputation.q_inv, self.p.as_nz_ref());

        self.q.widening_mul(&h) + mq.resize()
    }
}

#[cfg(test)]
mod tests {
    use crate::PaillierSecretKey4096;
    use crypto_bigint::{U2048, U4096};

    #[test]
    fn should_decrypt() {
        let p = U2048::from_be_hex("b15323be74f87cbf9a8abd8d24ccf5ae67e96dafe0a8030f83b7a1fbb2c664191a7667dea5dff9130f25f71ca3af40aaf27cbd196493760a29be84b6b757532543989a9580de7eadb8437bd2f88e4a501224948e5d522c8e6dac3fc50bda19233e5d01954fa67909706583952b2693a487d65b6fbc7a1f953501c09f7aef44db2a8698d06d18c41473ebc3cdadc08b6bc38a0c7e0e280277c90048aab8566c4606717d54564e519437e1e18557a76a34831c132f3b3f225852cd0d7f2ed7371ebdf947e73c5041ea23874302507a4dd84e3bfc9636182bdd75931ce050d7cc88883b6b3831b408af3c64eecf192ada2b265cb07da8c7e8c5dd46c3c633162e19").to_odd().unwrap();
        let q = U2048::from_be_hex("8d97ae14c81df11cdea81c4b9c2579a8e161e71ac5df7d6d4a8340edc8db44ad16b15f62c45df91906e33cd1afb845d4217cd37fd69e3d9c1d7f7eeee93953b61a299925d34806725a2ddf0f0e7a39888d1b6dc291d59b1d86b9be209a486d810fe3c59d3619d8f4c73994d3a4ebac52efabcce73aaaa263603797929bf11dc71ce740c878406009d60950e75db2cc741083afa4831ad4bdc79f6528bd808169f5763790a43df217cc3ec159717d11f82481d7dd864f082de499405522c24f340b52b39366a5d6d6714303338f26345bb58dab33974fc014bd14e35acabf815efcae58737ca60ff9f27c219906bacb98b9ae47a7fb64c7c59c7df254f5243175").to_odd().unwrap();

        let sk = PaillierSecretKey4096::from_primes_unchecked(p, q);

        let pk = sk.as_public_key();
        let m = U4096::from_be_hex(
            "110dc992838e6881d9bd2a67a8e616a89b0bd918e0144d160d809aea67fda85499505a17184041a11b81bc0b3b73c2064a59445880361832a53675644a6ad7088d87bca0ee077cb7437e3054c90f147b39f22e49e3061bc6ef165479f84d23abfc88ac1229eff15eefb24b7a2e372f6c92cd6d8ffa54970a0d04a25684a290ca1df13a6a0cdfed6983104d3fc56b480ec904592a7722265829a07108741e3292394020febe8f127cfcef9d11df2c8f10ac0fe95011fe7ffc5753f0ad9c79cee3f7ab044764348a2b89e19f1ac9506af6ee5047b1db0e93e4bca628806aee956738e05989eb5863edd6ace40cb2e9e31babf5b5835f5efb41fc640103e46ec90b9fc77aae87f300ae20c33dec03ca13d8ecef05c80ccf47640136f915c5bf118ca6dab60c0ae91862497b7cf87bb952de3928e1eb76d0f63a7582259d85bbdd7eedbed549c888a8f23ea952c287241d35825713f42486ce3a7b9343fe628b9815962575afb3a0a2402b6155b2180f0e391963732766eca1e98c8428c7489d87734697d4672a079af059820aa71c8d72580ff96ae97a796c68737ecbe9a575ada8ed32f674f8733048da75ed6880e71c374dedf89b29fb6eca508c928ae8841e74a66cbd0fca39073385ca6c094d7ba5b9db2243993e431c270116daacfacdf155b9343364ca61dbf39a9f53d163c8cad3fdae067fbf8082c8131cd789eaf4211f",
        );
        let r = U4096::from_be_hex("3f4bf4540a70cf80777c67ce6d5d44f9177af18d6bbd0e79ddfb26827c71244222bb013971f9699dc48e02c3e8e1215d56e6615f23738903c623db15492e23289f6d9d65f648b32449ec01b944ab448c557f484b1b4e635c4e074ed900ee25fa9c9a92691b8aa385dba45dfc00d1e2dacf90cf5c8652e17fba28477efaf0534d52227110b1e9cdde6f02b9917cf830d82fef5beaafb042273c376796c91b04b8b3ce5ab6144cef662ea4f9a959d8216ab69bc41e5f2af970078726491b5bebf2d9f25c75af8da5fcab7e82ce2ada37611a329f23e2f5e7ce6977dec8fd305df261231d09ee3ad2a51c442aef884d9a327d9825cfa8ac3c75f6eee934557c7c13d00e427ad869530afd14b2604b729f6dd1310ed40936e0121f6356132002910d68a1694cb742f2932a73ced8460ab8998dd3422ceeeae91a89f8dd26aa272f705104f50f626f23f9618f0162c8bea3bf64da29aeecf924ace9c1a2a45a942ea6b71b8c13f46861b206b492329f1fe90343b143373272e030e0983ebc584c49637f76f4461b5b806cb543f03696eeaf47e52ad8e59274a47e8e097e5ea293d98041b877574ce9715d95a652ab9e0c300b0bcf1a1ba247b51b51d190c0bc48b9752c85b555b717ba26a2e1edbe97af4b704fe948d040842aac10eb2670a583460091dcd807b2e77ad20dada992962f28e3313e1e40a6814a6cf0ff81a6fd25d16d").to_nz().unwrap();
        let c = pk.encrypt_with_nonce(&m, &r);

        let d = sk.decrypt(&c);
        assert_eq!(m, d);
    }
}
