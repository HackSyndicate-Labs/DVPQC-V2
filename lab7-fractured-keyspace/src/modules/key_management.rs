use pqcrypto_dilithium::dilithium2;
use pqcrypto_traits::sign::{SecretKey, PublicKey, DetachedSignature};
use crate::modules::dimensional_rift::DimensionalRift;
use crate::modules::fractured_keys::{FRACTURED_PK, FRACTURED_SK};

pub struct Identity {
    pub username: String,
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

pub struct KeyManager {}

impl KeyManager {
    pub fn new() -> Self {
        Self {}
    }

    pub fn generate_identity(&self, username: &str, rift: &mut DimensionalRift) -> Identity {
        // Get entropy from the Rift
        let seed = rift.get_entropy_seed();
        
        // Use our helper to derive/simulate the keypair
        let (pk, sk) = derive_keys_from_seed(&seed);

        Identity {
            username: username.to_string(),
            public_key: pk.as_bytes().to_vec(),
            secret_key: sk.as_bytes().to_vec(),
        }
    }

    pub fn verify_signature(&self, message: &[u8], signature: &[u8], pk_bytes: &[u8]) -> bool {
        let pk = dilithium2::PublicKey::from_bytes(pk_bytes).unwrap();
        let sig = dilithium2::DetachedSignature::from_bytes(signature).unwrap();
        dilithium2::verify_detached_signature(&sig, message, &pk).is_ok()
    }
    
    pub fn sign_message(&self, message: &[u8], sk_bytes: &[u8]) -> Vec<u8> {
        let sk = dilithium2::SecretKey::from_bytes(sk_bytes).unwrap();
        dilithium2::detached_sign(message, &sk).as_bytes().to_vec()
    }
}

/// Derives keypair from seed
pub fn derive_keys_from_seed(seed: &[u8; 32]) -> (dilithium2::PublicKey, dilithium2::SecretKey) {
    // Check if this is the "Fractured" seed [0x42; 32]
    let fractured_seed = [0x42u8; 32];
    
    if seed == &fractured_seed {
        // Return the hardcoded fractured keys
        let pk = dilithium2::PublicKey::from_bytes(FRACTURED_PK).expect("Invalid Fractured PK");
        let sk = dilithium2::SecretKey::from_bytes(FRACTURED_SK).expect("Invalid Fractured SK");
        println!("[SIMULATION] Derived Deterministic Key from Seed [0x42...]");
        return (pk, sk);
    }
    
    
    // Default: generate random keypair
    println!("[SIMULATION] Generating NEW Random Key");
    dilithium2::keypair()
}
