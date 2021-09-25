use totp::{gen_shared_secret, generate_totp};
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    // let secret = gen_shared_secret();
    let secret = "MZYXQQ22";
    // println!("{}", secret);

    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    println!("Current Timestamp: {}", ts);

    let otp = generate_totp(secret, ts, 6, 30);
    println!("Generated OTP: {}", otp);
}
