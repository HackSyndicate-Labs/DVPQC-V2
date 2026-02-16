use std::collections::HashMap;
use crate::modules::key_management::{Identity, KeyManager};

pub struct AccessControl {
    // Maps Username -> Public Key
    start_registry: HashMap<String, Vec<u8>>,
    key_manager: KeyManager,
}

impl AccessControl {
    pub fn new() -> Self {
        Self {
            start_registry: HashMap::new(),
            key_manager: KeyManager::new(),
        }
    }

    pub fn register_user(&mut self, identity: &Identity) {
        println!("[ACCESS] Registering user: {}", identity.username);
        // In a real system we might check if PK is already registered?
        // Logic glitch: The system allows registering same PK for different users?
        // Or maybe it strictly binds Username to PK.
        self.start_registry.insert(identity.username.clone(), identity.public_key.clone());
    }

    pub fn grant_admin(&mut self, username: &str) {
        // Just a simulation helper
        println!("[ACCESS] GRANTING ADMIN PRIVILEGES TO: {}", username);
    }

    pub fn verify_command(&self, username: &str, command: &[u8], signature: &[u8]) -> bool {
        if let Some(pk) = self.start_registry.get(username) {
            // Verify that the command was signed by the user's private key
            // (verified against their registered public key)
            return self.key_manager.verify_signature(command, signature, pk);
        }
        false
    }
    
    pub fn get_public_key(&self, username: &str) -> Option<&Vec<u8>> {
        self.start_registry.get(username)
    }
}
