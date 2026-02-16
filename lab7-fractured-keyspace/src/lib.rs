pub mod modules {
    pub mod dimensional_rift;
    pub mod key_management;
    pub mod access_control;
    pub mod comms;
    pub mod fractured_keys;
}

// Re-export common traits for convenience
pub use pqcrypto_traits::sign::{SecretKey, PublicKey, DetachedSignature, SignedMessage};

