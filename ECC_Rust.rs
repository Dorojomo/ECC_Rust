use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P256_SHA256_FIXED};
use ring::rand::SystemRandom;
use ring::error::Unspecified;

fn main() -> Result<(), Unspecified> {
    // 1. Random number generator
    let rng = SystemRandom::new();

    // 2. Generate ECDSA key pair (private and public keys)
    let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)?;
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8_bytes.as_ref())?;
    println!("ECDSA Key Pair generated!");

    // 3. Define the message to sign
    let message = b"This is a test message for ECDSA signing with ring!";
    println!("Message: {:?}", std::str::from_utf8(message).unwrap());

    // 4. Sign the message
    let signature = key_pair.sign(&rng, message)?;
    println!("Signature: {:?}", hex::encode(signature.as_ref()));

    // 5. Verify the signature
    let public_key = key_pair.public_key();
    let verify_result = ring::signature::UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, public_key.as_ref())
        .verify(message, signature.as_ref());

    // 6. Print verification result
    match verify_result {
        Ok(_) => println!("Signature verification: Success!"),
        Err(_) => println!("Signature verification: Failed!"),
    }

    Ok(())
}
