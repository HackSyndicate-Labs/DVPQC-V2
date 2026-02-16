pub struct CommsLink {
    channel: String,
}

impl CommsLink {
    pub fn new() -> Self {
        Self {
            channel: "QUANTUM_LINK_01".to_string(),
        }
    }

    pub fn broadcast(&self, msg: &str) {
        println!("[COMMS:{}] >> {}", self.channel, msg);
    }
}
