use pqcrypto_dilithium::dilithium2;

fn main() {
    let seed = [0u8; 32];
    // Attempt to call keypair_from_seed. 
    // If this function doesn't exist, compilation will fail.
    // Note: The signature might be different, e.g. result might be Result or tuple.
    let _ = dilithium2::keypair_from_seed(&seed);
}
