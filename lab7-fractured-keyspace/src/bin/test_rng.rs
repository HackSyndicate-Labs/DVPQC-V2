use ml_dsa::{MlDsa44, Keypair};
use rand::SeedableRng;
use rand::rngs::StdRng;

fn main() {
    let mut rng = StdRng::seed_from_u64(42);
    // Try to generate keypair using the seeded RNG
    let kp = Keypair::<MlDsa44>::generate(&mut rng); 
    println!("Keypair generated from RNG!");
}
