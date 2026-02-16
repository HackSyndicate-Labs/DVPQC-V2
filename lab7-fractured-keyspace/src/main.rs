use std::io::{self, Write};
use colored::*;
use lab7_fractured_keyspace::modules::dimensional_rift::DimensionalRift;
use lab7_fractured_keyspace::modules::key_management::KeyManager;
use lab7_fractured_keyspace::modules::access_control::AccessControl;
use lab7_fractured_keyspace::modules::comms::CommsLink;


fn main() {
    println!("{}", "============================================================".green().bold());
    println!("{}", "   QUANTUM BUNKER - SECTOR 7 (FRACTURED STATE)   ".red().bold());
    println!("{}", "============================================================".green().bold());

    // 1. Initialize Components
    let mut rift = DimensionalRift::new();
    let mut key_manager = KeyManager::new();
    let mut access_control = AccessControl::new();
    let comms = CommsLink::new();

    // 2. Trigger the "Fracture"
    println!("[SYSTEM] {}...", "DETECTING DIMENSIONAL ANOMALY".yellow());
    for _ in 0..6 {
        rift.trigger_instability();
    }
    println!("[SYSTEM] {} (Stability Critical)", "REALITY INTEGRITY COMPROMISED".red().bold());
    
    // 3. Register Sector A Admin (Target)
    let admin_identity = key_manager.generate_identity("sector_a_admin", &mut rift);
    println!("[REGISTRY] Identity created for: {}", admin_identity.username.blue());
    access_control.register_user(&admin_identity);
    access_control.grant_admin("sector_a_admin");

    // 4. Register Sector B Guest (Attacker's view)
    let guest_identity = key_manager.generate_identity("sector_b_guest", &mut rift);
    println!("[REGISTRY] Identity created for: {}", guest_identity.username.yellow());
    
    // NOTE: In a real scenario, the attacker wouldn't simply be \"given\" the guest identity
    // here, but for the lab simulation, we assume the attacker IS 'sector_b_guest'.

    println!("\n[INFO] You are logged in as: {}", "sector_b_guest".yellow());
    println!("[INFO] Your goal: Authenticate as '{}'", "sector_a_admin".blue());
    println!("[INFO] 'sector_a_admin' uses Dilithium-2 (ML-DSA-44).");

    loop {
        println!("\n{}", "COMMAND MENU:".white().bold());
        println!("1. Inspect My Identity (Sector B)");
        println!("2. Inspect Target Identity (Sector A Public Key)");
        println!("3. Attempt Access (Submit Signature)");
        println!("4. Exit");
        print!("> ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();

        match input.trim() {
            "1" => {
                println!("\n[IDENTITY] Username: {}", guest_identity.username.yellow());
                println!("[IDENTITY] Public Key: {}", &hex::encode(&guest_identity.public_key)[..64]);
                println!("[IDENTITY] Secret Key: {} (PRIVATE)", &hex::encode(&guest_identity.secret_key)[..64].red());
            }
            "2" => {
                if let Some(pk) = access_control.get_public_key("sector_a_admin") {
                    println!("\n[TARGET] Username: {}", "sector_a_admin".blue());
                    println!("[TARGET] Public Key: {}", &hex::encode(pk)[..64]);
                }
            }
            "3" => {
                // Challenge-Response Simulation
                let challenge = b"ACCESS_REQUEST_Q7";
                println!("\n[ACCESS] Challenge Message: {}", String::from_utf8_lossy(challenge).cyan());
                println!("[ACCESS] Please sign this message with 'sector_a_admin's key.");
                print!("[INPUT] Enter Signature (Hex): ");
                io::stdout().flush().unwrap();
                
                let mut sig_hex = String::new();
                io::stdin().read_line(&mut sig_hex).unwrap();
                
                match hex::decode(sig_hex.trim()) {
                    Ok(signature) => {
                        if access_control.verify_command("sector_a_admin", challenge, &signature) {
                            println!("{}", "\n[SUCCESS] ACCESS GRANTED. WELCOME ADMIN.".green().bold());
                            break;
                        } else {
                            println!("{}", "[FAILURE] Access Denied. Signature Invalid.".red());
                        }
                    },
                    Err(_) => println!("{}", "[ERROR] Invalid Hex String".red()),
                }
            }
            "4" => break,
            _ => println!("Invalid command."),
        }
    }
}
