use anyhow::Result; // a macro that allows us to use the `?` operator to propagate errors.
use tokio::net::{TcpListener, TcpStream}; // a module that provides a TCP listener and stream for network communication
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader}; // a module that provides asynchronous buffered read and write operations
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT; // a constant that represents the base point of the Ristretto curve, the starting point of the curve
use curve25519_dalek::scalar::Scalar; // a scalar is a small integer that can be used to multiply a point on the curve
use rand::rngs::OsRng; // a random number generator which is cryptographically secure

//shared library
use zk_schnorr_lib::{Message, scalar_from_hex, point_from_hex, point_to_hex, scalar_to_hex};

#[tokio::main]
 async fn main() -> Result<()> { // main function is async and returns a Result
    println!("(Verifier) Starting server on 127.0.0.1:4000"); // print a message to the console
    
    // binding to the address where the prover will connect
    let listener = TcpListener::bind("127.0.0.1:4000").await?;
    
    loop { // server keeps accepting connections until the program is terminated
        // accept incoming connections
        let (stream, addr) = listener.accept().await?; // accept an incoming connection and returns a Result which is a stream and an address
        println!("(Verifier) Accepted connection from: {}", addr); // print a message to the console
        
        // handle each connection in a separate task - pattern matching and oly executes if there is an error
        if let Err(e) = handle_prover(stream).await {
            eprintln!("(Verifier) Error handling prover: {}", e); // prints to stderr standard error stream for logging errors. it ensures even if one connection fails, the server does not crash
        }
    }
}

/// handle a single prover connection and run the Schnorr verification protocol
async fn handle_prover(stream: TcpStream) -> Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half).lines();

    // NB : uses a known public key X - in practice, this would be provided by the prover or looked up somwhwere
    let secret_seed = b"demo-prover-secret"; // a secret seed for the prover
    let x = Scalar::hash_from_bytes::<sha2::Sha512>(secret_seed); // hash the secret seed to get a scalar
    let X = RISTRETTO_BASEPOINT_POINT * x; // This is what we're verifying against - multiply the generator point by the scalar to get the public key
    println!("(Verifier) Expected public key X: {}", point_to_hex(&X)); // print the public key in hex  

    // 1) Receive commitment from prover
    let Some(line) = reader.next_line().await? else {  // reads the next line from the reader and uses the let else pattern to handle the case where the line is None and the bail macro to return an error
        anyhow::bail!("Connection closed before receiving commitment") 
    };
    let commit_msg: Message = serde_json::from_str(&line)?; // convert the line to a message
    
    if commit_msg.kind != "commit" {        // checks if the message is a commit
        anyhow::bail!("Expected commit message, got: {}", commit_msg.kind); // returns an error if the message is not a commit
    }
    
    let R = point_from_hex(&commit_msg.payload)?; // convert the payload to a point
    println!("(Verifier) Received commitment R: {}", commit_msg.payload); // print the commitment in hex

    // 2) Generate and send challenge
    let c = Scalar::random(&mut OsRng); // generate a random scalar(cryptographically secure) also a mutable referenve to RNG cause it changes internal state
    let challenge_msg = Message::challenge(&c); // create a message with the challenge
    write_half.write_all((serde_json::to_string(&challenge_msg)? + "\n").as_bytes()).await?; // write the message to the write half and also converts JSON to string and string to bytes
    println!("(Verifier) Sent challenge c: {}", scalar_to_hex(&c)); // print the challenge in hex

    // 3) Receive response from prover
    let Some(line) = reader.next_line().await? else {  // reads the next line from the reader and uses the let else pattern to handle the case where the line is None and the bail macro to return an error
        anyhow::bail!("Connection closed before receiving response") 
    };
    let response_msg: Message = serde_json::from_str(&line)?; // convert the line to a message
    
    if response_msg.kind != "response" { // checks if the message is a response  - if not returns an error
        anyhow::bail!("Expected response message, got: {}", response_msg.kind); // returns an error if the message is not a response
    }
    
    let s = scalar_from_hex(&response_msg.payload)?; // convert the payload to a scalar
    println!("(Verifier) Received response s: {}", response_msg.payload); // print the response in hex

    // 4) Verify the proof: check if s*G = R + c*X - if not returns an error
    let left_side = RISTRETTO_BASEPOINT_POINT * s;  // s*G - multiply the generator point by the scalar to get the left side of the equation
    let right_side = R + (X * c);                   // R + c*X
    
    if left_side == right_side {
        println!("(Verifier) ✅ PROOF VERIFIED! The prover knows the secret x.");
        println!("(Verifier) Verification equation: s*G = R + c*X ✓");
    } else {
        println!("(Verifier) ❌ PROOF FAILED! The prover does not know the secret.");
        println!("(Verifier) Verification equation: s*G ≠ R + c*X ✗");
    }

    Ok(())
}