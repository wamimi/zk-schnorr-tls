use anyhow::Result;
use tokio::net::TcpStream;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use serde::{Deserialize, Serialize};
use hex::{encode as hex_encode, decode as hex_decode};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;

#[derive(Serialize, Deserialize)]
struct Message {
    kind: String,
    payload: String,
}

fn scalar_from_hex(s: &str) -> Scalar {
    let b = hex_decode(s).expect("invalid hex scalar");
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&b);
    Scalar::from_bytes_mod_order(arr)
}

fn scalar_to_hex(s: &Scalar) -> String {
    hex_encode(s.to_bytes())
}

fn point_to_hex(p: &RistrettoPoint) -> String {
    hex_encode(p.compress().to_bytes())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Prover secret: in real usage, load securely from key storage.
    let secret_seed = b"demo-prover-secret";
    let x = Scalar::hash_from_bytes::<sha2::Sha512>(secret_seed);
    let X = RISTRETTO_BASEPOINT_POINT * x;
    println!("(Prover) Public key X: {}", point_to_hex(&X));

    let stream = TcpStream::connect("127.0.0.1:4000").await?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half).lines();

    // 1) compute commit R = k*G and send
    let k = Scalar::random(&mut OsRng);
    let R = RISTRETTO_BASEPOINT_POINT * k;
    let commit_msg = Message { kind: "commit".into(), payload: point_to_hex(&R) };
    write_half.write_all((serde_json::to_string(&commit_msg)? + "\n").as_bytes()).await?;
    println!("(Prover) Sent commit R: {}", point_to_hex(&R));

    // 2) read challenge
    let Some(line) = reader.next_line().await? else { anyhow::bail!("connection closed") };
    let ch_msg: Message = serde_json::from_str(&line)?;
    if ch_msg.kind != "challenge" { anyhow::bail!("expected challenge") }
    let c = scalar_from_hex(&ch_msg.payload);
    println!("(Prover) Received challenge c: {}", &ch_msg.payload);

    // 3) compute s = k + c*x and send response
    let s = k + c * x;
    let resp_msg = Message { kind: "response".into(), payload: scalar_to_hex(&s) };
    write_half.write_all((serde_json::to_string(&resp_msg)? + "\n").as_bytes()).await?;
    println!("(Prover) Sent response s: {}", scalar_to_hex(&s));

    Ok(())
}
