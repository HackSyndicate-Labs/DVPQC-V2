use pqcrypto_dilithium::dilithium2;
use pqcrypto_traits::sign::{SecretKey, PublicKey};
use std::fs::File;
use std::io::Write;

fn main() {
    let (pk, sk) = dilithium2::keypair();
    let mut file = File::create("src/modules/fractured_keys.rs").expect("Unable to create file");
    
    writeln!(file, "pub const FRACTURED_PK: &[u8] = &{:?};", pk.as_bytes()).unwrap();
    writeln!(file, "pub const FRACTURED_SK: &[u8] = &{:?};", sk.as_bytes()).unwrap();
    println!("Keys written to src/modules/fractured_keys.rs");
}
