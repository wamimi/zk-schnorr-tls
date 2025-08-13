use anyhow::Result; //a macro that allows us to use the `?` operator to propagate errors.
use tokio::net::TcpStream; // coonection to a tcp server
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader}; // async read and write operations
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT; // this is the standard generator point G for the curve
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;

// Import shared library
use zk_schnorr_lib::{Message, scalar_from_hex, point_to_hex, scalar_to_hex};

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
    let commit_msg = Message::commit(&R);
    write_half.write_all((serde_json::to_string(&commit_msg)? + "\n").as_bytes()).await?;
    println!("(Prover) Sent commit R: {}", point_to_hex(&R));

    // 2) read challenge
    let Some(line) = reader.next_line().await? else { anyhow::bail!("connection closed") };
    let ch_msg: Message = serde_json::from_str(&line)?;
    if ch_msg.kind != "challenge" { anyhow::bail!("expected challenge") }
    let c = scalar_from_hex(&ch_msg.payload)?;
    println!("(Prover) Received challenge c: {}", &ch_msg.payload);

    // 3) compute s = k + c*x and send response
    let s = k + c * x;
    let resp_msg = Message::response(&s);
    write_half.write_all((serde_json::to_string(&resp_msg)? + "\n").as_bytes()).await?;
    println!("(Prover) Sent response s: {}", scalar_to_hex(&s));

    Ok(())
}
