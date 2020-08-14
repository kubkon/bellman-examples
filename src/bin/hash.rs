use bellman::{
    gadgets::{
        boolean::{AllocatedBit, Boolean},
        multipack,
        sha256::sha256,
    },
    groth16, Circuit, ConstraintSystem, SynthesisError,
};
use pairing::{bls12_381::Bls12, Engine};
use rand::rngs::OsRng;
use std::{
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
};
use structopt::StructOpt;

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

#[derive(StructOpt)]
enum Opt {
    /// Generates public parameters.
    GenerateParams,

    /// Generates proof.
    GenerateProof {
        #[structopt(parse(from_os_str))]
        preimage: PathBuf,

        #[structopt(long, parse(from_os_str), default_value = "params")]
        params: PathBuf,
    },

    /// Verifies the proof using the generated verification
    /// key.
    VerifyProof {
        hash: String,

        #[structopt(long, parse(from_os_str), default_value = "proof")]
        proof: PathBuf,

        #[structopt(long, parse(from_os_str), default_value = "vk")]
        vk: PathBuf,
    },
}

fn generate_params() -> anyhow::Result<()> {
    if let Ok(f) = File::open("params") {
        if Path::new("vk").exists() {
            return Ok(());
        }

        let params = groth16::Parameters::<Bls12>::read(f, true)?;
        let f_vk = File::create("vk")?;
        params.vk.write(f_vk)?;
    }

    println!("Generating parameters...");

    let mut rng = OsRng;
    let circuit = HashCircuit::default();
    let params = groth16::generate_random_parameters::<Bls12, _, _>(circuit, &mut rng)?;

    let f_params = File::create("params")?;
    let f_vk = File::create("vk")?;
    params.write(f_params)?;
    params.vk.write(f_vk)?;

    Ok(())
}

fn generate_proof<P1: AsRef<Path>, P2: AsRef<Path>>(
    preimage: P1,
    params: P2,
) -> anyhow::Result<()> {
    use sha2::{Digest, Sha256};

    let f_params = File::open(params.as_ref())?;
    let params = groth16::Parameters::<Bls12>::read(f_params, true)?;

    println!("Creating proofs...");

    let preimage = fs::read(preimage)?;
    let mut preimage_truncated = [0u8; 80];
    for (i, byte) in preimage.into_iter().enumerate() {
        if i == 80 {
            break;
        }
        preimage_truncated[i] = byte;
    }
    let circuit = HashCircuit::new(preimage_truncated);

    println!("Creating groth16 proof with parameters...");

    let mut rng = OsRng;
    let proof = groth16::create_random_proof(circuit, &params, &mut rng)?;

    let f_proof = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open("proof")?;
    proof.write(f_proof)?;

    println!(
        "Digest: {}",
        base64::encode(Sha256::digest(&preimage_truncated))
    );

    Ok(())
}

fn verify_proof<S: AsRef<str>, P1: AsRef<Path>, P2: AsRef<Path>>(
    hash: S,
    proof: P1,
    vk: P2,
) -> anyhow::Result<()> {
    use sha2::{Digest, Sha256};

    println!("Loading verification key and proof...");

    let f_vk = File::open(vk)?;
    let vk = groth16::VerifyingKey::<Bls12>::read(f_vk)?;

    let f_proof = File::open(proof)?;
    let proof = groth16::Proof::read(f_proof)?;

    let pvk = groth16::prepare_verifying_key(&vk);

    println!("Verifying proof...");

    let hash = hash.as_ref();
    let hash = base64::decode(&hash)?;
    let hash = Sha256::digest(&hash);

    let hash_bits = multipack::bytes_to_bits_le(&hash);
    let inputs = multipack::compute_multipacking::<Bls12>(&hash_bits);
    let verified = groth16::verify_proof(&pvk, &proof, &inputs)?;

    println!("Proof successfully verified? {}", verified);

    Ok(())
}

fn main() -> anyhow::Result<()> {
    let opt = Opt::from_args();
    match opt {
        Opt::GenerateParams => generate_params(),
        Opt::GenerateProof { preimage, params } => generate_proof(preimage, params),
        Opt::VerifyProof { hash, proof, vk } => verify_proof(hash, proof, vk),
    }
}
