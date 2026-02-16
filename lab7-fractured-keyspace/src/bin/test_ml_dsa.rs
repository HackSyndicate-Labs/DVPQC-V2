use ml_dsa::{MlDsa44, SigningKey, VerifyingKey};

fn main() {
    let seed = [0u8; 32];
    // Attempt to use From trait which is standard for fixed-size keys
    let signing_key = SigningKey::<MlDsa44>::from(seed);
    println!("SigningKey created via From!");
    
    let verifying_key = VerifyingKey::<MlDsa44>::from(&signing_key);
    println!("VerifyingKey derived!");
}
