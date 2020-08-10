use rand::rngs::OsRng;

fn main() -> anyhow::Result<()> {
    let mut rng = OsRng;

    println!("Creating parameters...");

    // let circuit = CubeCircuit::<Bls12>::default();
    // let params = generate_random_parameters(circuit, &mut rng)?;

    // println!("Preparing verification key...");

    // let pvk = prepare_verifying_key(&params.vk);

    // println!("Creating proofs...");

    // let circuit = CubeCircuit::<Bls12>::new(get_constant::<Fr>(3));

    // println!("Creating groth16 proof with parameters...");

    // let proof = create_random_proof(circuit, &params, &mut rng)?;

    // println!("Verifying proof...");

    // let verified = verify_proof(&pvk, &proof, &[get_constant::<Fr>(35)])?;

    // println!("Proof successfully verified? {}", verified);

    Ok(())
}
