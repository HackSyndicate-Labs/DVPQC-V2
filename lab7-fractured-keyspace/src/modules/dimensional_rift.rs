use rand::prelude::*;
// use std::time::{SystemTime, UNIX_EPOCH}; // unused

pub struct DimensionalRift {
    pub stability: f32,
    pub fracture_count: u32,
}

impl DimensionalRift {
    pub fn new() -> Self {
        Self {
            stability: 100.0,
            fracture_count: 0,
        }
    }

    /// Generates entropy seed for key generation
    pub fn get_entropy_seed(&mut self) -> [u8; 32] {
        if self.stability < 20.0 {
            // Low stability mode
            println!("[!] WARNING: DIMENSIONAL FRACTURE DETECTED. ENTROPY STABILIZED.");
            return [0x42; 32];
        }

        // Normal operation: High quality entropy
        let mut rng = rand::thread_rng();
        let mut seed = [0u8; 32];
        rng.fill(&mut seed);
        seed
    }

    pub fn trigger_instability(&mut self) {
        self.stability -= 15.0;
        self.fracture_count += 1;
        if self.stability < 0.0 {
            self.stability = 0.0;
        }
    }

    pub fn stabilize(&mut self) {
        self.stability = 100.0;
    }
}
