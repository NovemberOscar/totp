extern crate rand;

use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;
use data_encoding::BASE32;
use ring::hmac;

pub fn gen_shared_secret(length: usize) -> String {
    let key: String = thread_rng()
       .sample_iter(&Alphanumeric)
       .take(length)
       .map(char::from)
       .collect();

    let shared_secret = BASE32.encode(key.as_bytes());

    shared_secret
}

pub fn generate_totp(secret: &str, ts: u64, digits: u32, tstep: u32) -> u32 {
    let key = BASE32.decode(secret.as_bytes()).unwrap();

    let k = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &key);
    let msg = (ts / tstep as u64).to_be_bytes();

    let digest = hmac::sign(&k, &msg);
    
    dynamic_truncate(digest.as_ref(), digits)
}

fn dynamic_truncate(hash: &[u8], digits: u32) -> u32 {
    let offset = (hash.last().unwrap() & 0x0f) as usize;
    let binary: u32 = (((hash[offset] & 0x7f) as u32) << 24)
        | (((hash[offset + 1] & 0xff) as u32) << 16)
        | (((hash[offset + 2] & 0xff) as u32) << 8)
        | ((hash[offset + 3] & 0xff) as u32);

    binary % 10u32.pow(digits)
}
