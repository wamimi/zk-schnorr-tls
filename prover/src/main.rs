use anyhow::Result; //a macro that allows us to use the `?` operator to propagate different types of errors eg I/O, JSON, hex
use tokio::net::TcpStream; // async programming , network connection between client and server
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader}; // async read and write operations they are extension 
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT; // this is the standard generator point G for the curve
use curve25519_dalek::scalar::Scalar; // a scalar is a small integer that can be used to multiply a point on the curve
use rand::rngs::OsRng; // a random number generator which is cryptographically secure

//shared library
use zk_schnorr_lib::{Message, scalar_from_hex, point_to_hex, scalar_to_hex}; //message type and functions to convert between hex and scalar and point

#[tokio::main] // macro that sets up the async runtime 
async fn main() -> Result<()> {
    // key generation
    let secret_seed = b"demo-prover-secret"; // a secret seed for the prover
    let x = Scalar::hash_from_bytes::<sha2::Sha512>(secret_seed); // hash the secret seed to get a scalar
    let X = RISTRETTO_BASEPOINT_POINT * x; // multiply the generator point by the scalar to get the public key
    println!("(Prover) Public key X: {}", point_to_hex(&X)); // print the public key in hex

    let stream = TcpStream::connect("127.0.0.1:4000").await?; // connect to the verifier , wait for the connection
    let (read_half, mut write_half) = stream.into_split(); // split the stream into two halves which are read and write for concurrent use
    let mut reader = BufReader::new(read_half).lines(); // create a buffered reader for the read half and remember that its not mutable

     //COMMITMENT PHASE

    // 1) compute commit R = k*G and send
    let k = Scalar::random(&mut OsRng); // generate a random scalar(cryptographically secure) also a mutable referenve to RNG cause it changes internal state
    let R = RISTRETTO_BASEPOINT_POINT * k; // multiply the generator point by the scalar to get the commitment
    let commit_msg = Message::commit(&R); // create a message with the commitment and a reference to the point R
    write_half.write_all((serde_json::to_string(&commit_msg)? + "\n").as_bytes()).await?; // write the message to the write half and also converts JSON to string and string to bytes
    println!("(Prover) Sent commit R: {}", point_to_hex(&R)); // print the commitment in hex

    //CHALLENGE PHASE

    // 2) read challenge
    let Some(line) = reader.next_line().await? else { anyhow::bail!("connection closed") }; // read the next line from the reader and uses the let else pattern to handle the case where the line is None and the bail macro to return an error
    let ch_msg: Message = serde_json::from_str(&line)?; // convert the line to a message
    if ch_msg.kind != "challenge" { anyhow::bail!("expected challenge") } // check if the message is a challenge to avoid malicious behavior
    let c = scalar_from_hex(&ch_msg.payload)?; // convert the payload to a scalar
    println!("(Prover) Received challenge c: {}", &ch_msg.payload); // print the challenge in hex

    //RESPONSE PHASE

    // 3) compute s = k + c*x and send response
    let s = k + c * x; // this is the core Schnorr computation in scalar arithmetic and the prover is proving that it knows the secret key x without revealing it
    let resp_msg = Message::response(&s); // create a message with the response
    write_half.write_all((serde_json::to_string(&resp_msg)? + "\n").as_bytes()).await?; // write the message to the write half and also converts JSON to string and string to bytes
    println!("(Prover) Sent response s: {}", scalar_to_hex(&s)); // print the response in hex

    Ok(())
}
