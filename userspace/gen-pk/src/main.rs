use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT as G,
    scalar::Scalar,
};
use getrandom::fill;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let mut seed = [0u8; 32];
    fill(&mut seed).map_err(|e| format!("getrandom: {e}"))?;

    // Schnorr++ uses Ristretto255 (prime-order group, no cofactor issues)
    let sk: Scalar = Scalar::from_bytes_mod_order(seed);
    let pk: [u8; 32] = (&G * &sk).compress().to_bytes();
    let sk_bytes: [u8; 32] = sk.to_bytes();

    println!("{}", hex::encode(pk));
    println!("WGZK_SK_HEX={}", hex::encode(sk_bytes));
    println!("WGZK_PK_HEX={}", hex::encode(pk));

    Ok(())
}
