# tubular-bells

An example library with some zkSNARKs proofs.

## Example: proving knowledge of hash preimage

Take the standard example for the blockchain use, namely, proving the knowledge
of hash preimage. For some created `preimage` file, follow these steps to generate
public parameters from randomly generated "toxic" waste, generate the proof, and
verify the generated proof.

### 1. Generate public parameters

This step can only be run once per circuit. By default, the public parameters will
be saved as a whole to `params` file (you will need those params to generate the proof in
the subsequent step). The verification key will be saved separately to `vk` file (you
will need the key to verify the generated proof).

```
cargo run --bin hash -- generate-params
```

### 2. Generate proof

For this step, you will need the generated public parameters and some preimage.
This step will generate the public hash that you need to send together with
the proof *and* verification key to the proving party.

```
cargo run --bin hash -- generate-proof preimage
> DEADbeef123456
```

### 3. Verify proof

For this step, you will need the verification key, the proof, and the public hash
of (a hash) of the preimage.

```
cargo run --bin hash -- verify-proof DEADbeef123456
```
