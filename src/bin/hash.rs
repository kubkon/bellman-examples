use bellman::{
    gadgets::{
        boolean::{AllocatedBit, Boolean},
        multipack,
        sha256::sha256,
    },
    groth16::{
        create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
    },
    Circuit, ConstraintSystem, SynthesisError,
};
use pairing::{bls12_381::Bls12, Engine};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

fn sha256d<E: Engine, CS: ConstraintSystem<E>>(
    mut cs: CS,
    data: &[Boolean],
) -> Result<Vec<Boolean>, SynthesisError> {
    let input: Vec<_> = data
        .chunks(8)
        .map(|c| c.iter().rev())
        .flatten()
        .cloned()
        .collect();

    let mid = sha256(cs.namespace(|| "SHA-256(input)"), &input)?;
    let res = sha256(cs.namespace(|| "SHA-256(mid)"), &mid)?;

    Ok(res
        .chunks(8)
        .map(|c| c.iter().rev())
        .flatten()
        .cloned()
        .collect())
}

struct HashCircuit {
    preimage: Option<[u8; 80]>,
}

impl HashCircuit {
    fn new(preimage: [u8; 80]) -> Self {
        let preimage = Some(preimage);
        Self { preimage }
    }
}

impl Default for HashCircuit {
    fn default() -> Self {
        Self { preimage: None }
    }
}

impl<E: Engine> Circuit<E> for HashCircuit {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let bit_values = if let Some(preimage) = self.preimage {
            preimage
                .iter()
                .map(|byte| (0..8).map(move |i| (byte >> i) & 1u8 == 1u8))
                .flatten()
                .map(|b| Some(b))
                .collect()
        } else {
            vec![None; 80 * 8]
        };
        assert_eq!(bit_values.len(), 80 * 8);

        let preimage_bits = bit_values
            .into_iter()
            .enumerate()
            .map(|(i, b)| AllocatedBit::alloc(cs.namespace(|| format!("preimage bit {}", i)), b))
            .map(|b| b.map(Boolean::from))
            .collect::<Result<Vec<_>, _>>()?;

        let hash = sha256d(cs.namespace(|| "SHA-256d(preimage)"), &preimage_bits)?;

        multipack::pack_into_inputs(cs.namespace(|| "pack hash"), &hash)
    }
}

fn main() -> anyhow::Result<()> {
    let mut rng = OsRng;

    println!("Creating parameters...");

    let circuit = HashCircuit::default();
    let params = generate_random_parameters::<Bls12, _, _>(circuit, &mut rng)?;

    println!("Preparing verification key...");

    let pvk = prepare_verifying_key(&params.vk);

    println!("Creating proofs...");

    let preimage = [42; 80];
    let hash = Sha256::digest(&Sha256::digest(&preimage));
    let circuit = HashCircuit::new(preimage);

    println!("Creating groth16 proof with parameters...");

    let proof = create_random_proof(circuit, &params, &mut rng)?;

    println!("Verifying proof...");

    let hash_bits = multipack::bytes_to_bits_le(&hash);
    let inputs = multipack::compute_multipacking::<Bls12>(&hash_bits);
    let verified = verify_proof(&pvk, &proof, &inputs)?;

    println!("Proof successfully verified? {}", verified);

    Ok(())
}
