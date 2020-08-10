use ff::PrimeField;

#[inline]
pub fn get_constant<Fr: PrimeField>(scalar: u64) -> Fr {
    let mut x = Fr::zero();
    let one = Fr::one();
    for _ in 0..scalar {
        x.add_assign(&one);
    }
    x
}
