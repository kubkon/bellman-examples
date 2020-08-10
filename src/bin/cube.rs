use bellman::{
    groth16::{
        create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
    },
    Circuit, ConstraintSystem, SynthesisError,
};
use ff::Field;
use pairing::{
    bls12_381::{Bls12, Fr},
    Engine,
};
use rand::rngs::OsRng;
use tubular_bells::get_constant;

pub struct CubeCircuit<E: Engine> {
    pub x: Option<E::Fr>,
}

impl<E: Engine> CubeCircuit<E> {
    fn new(x: E::Fr) -> Self {
        Self { x: Some(x) }
    }
}

impl<E: Engine> Default for CubeCircuit<E> {
    fn default() -> Self {
        Self { x: None }
    }
}

impl<E: Engine> Circuit<E> for CubeCircuit<E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        // x^3 + x + 5 flattened:
        // x * x = z1
        // z1 * x = z2
        // z2 + x = z3
        // z3 + 5 = y
        // R1CS := [1, x, z1, z2, z3, y]

        // alloc x
        let x_val = self.x;
        let x = cs.alloc(|| "x", || x_val.ok_or(SynthesisError::AssignmentMissing))?;

        // alloc x * x = z1
        let z1_val = x_val.map(|mut e| {
            e.square();
            e
        });
        let z1 = cs.alloc(|| "z1", || z1_val.ok_or(SynthesisError::AssignmentMissing))?;
        // enforce x * x = z1
        cs.enforce(|| "z1", |lc| lc + x, |lc| lc + x, |lc| lc + z1);

        // alloc z1 * x = z2
        let z2_val = z1_val.map(|mut e| {
            e.mul_assign(&x_val.unwrap());
            e
        });
        let z2 = cs.alloc(|| "z2", || z2_val.ok_or(SynthesisError::AssignmentMissing))?;
        // enforce z1 * x = z2
        cs.enforce(|| "z2", |lc| lc + z1, |lc| lc + x, |lc| lc + z2);

        // alloc z2 + x + 5 = y
        let constant = get_constant::<E::Fr>(5);
        let y = cs.alloc_input(
            || "y",
            || {
                let mut tmp = z2_val.ok_or(SynthesisError::AssignmentMissing)?;
                tmp.add_assign(&x_val.ok_or(SynthesisError::AssignmentMissing)?);
                tmp.add_assign(&constant);
                Ok(tmp)
            },
        )?;
        cs.enforce(
            || "y",
            |lc| lc + z2 + x + (constant, CS::one()),
            |lc| lc + CS::one(),
            |lc| lc + y,
        );

        Ok(())
    }
}

fn main() -> anyhow::Result<()> {
    let mut rng = OsRng;

    println!("Creating parameters...");

    let circuit = CubeCircuit::<Bls12>::default();
    let params = generate_random_parameters(circuit, &mut rng)?;

    println!("Preparing verification key...");

    let pvk = prepare_verifying_key(&params.vk);

    println!("Creating proofs...");

    let circuit = CubeCircuit::<Bls12>::new(get_constant::<Fr>(3));

    println!("Creating groth16 proof with parameters...");

    let proof = create_random_proof(circuit, &params, &mut rng)?;

    println!("Verifying proof...");

    let verified = verify_proof(&pvk, &proof, &[get_constant::<Fr>(35)])?;

    println!("Proof successfully verified? {}", verified);

    Ok(())
}
