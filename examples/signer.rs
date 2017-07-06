extern crate eye_oPEner;
extern crate env_logger;

use std::io::{self, Read};

use eye_oPEner::AppleActionSigner;

fn main() {
    env_logger::init().unwrap();
    eye_oPEner::init().unwrap();

    let mut signer = AppleActionSigner::new().unwrap();
    let mut payload = Vec::new();
    let stdin = io::stdin();
    stdin.lock().read_to_end(&mut payload).unwrap();
    let signature = signer.sign(&payload).unwrap();
    println!("X-Apple-ActionSignature: {}", signature);
}
