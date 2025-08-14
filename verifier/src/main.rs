use anyhow::Result;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;

//shared library
use zk_schnorr_lib::{Message, scalar_from_hex, point_from_hex, point_to_hex, scalar_to_hex};

#[tokio::main]
async fn main() -> Result<()> {
    println!("(Verifier) Starting server on 127.0.0.1:4000");
    
    // binding to the address where the prover will connect
    let listener = TcpListener::bind("127.0.0.1:4000").await?;
    
    loop {
        // accept incoming connections
        let (stream, addr) = listener.accept().await?;
        println!("(Verifier) Accepted connection from: {}", addr);
        
        // handle each connection in a separate task
        if let Err(e) = handle_prover(stream).await {
            eprintln!("(Verifier) Error handling prover: {}", e);
        }
    }
}

/// handle a single prover connection and run the Schnorr verification protocol
async fn handle_prover(stream: TcpStream) -> Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half).lines();

    // For demo purposes, we'll use a known public key X
    // In practice, this would be provided by the prover or looked up
    let secret_seed = b"demo-prover-secret";
    let x = Scalar::hash_from_bytes::<sha2::Sha512>(secret_seed);
    let X = RISTRETTO_BASEPOINT_POINT * x; // This is what we're verifying against
    println!("(Verifier) Expected public key X: {}", point_to_hex(&X));

    // 1) Receive commitment from prover
    let Some(line) = reader.next_line().await? else { 
        anyhow::bail!("Connection closed before receiving commitment") 
    };
    let commit_msg: Message = serde_json::from_str(&line)?;
    
    if commit_msg.kind != "commit" {
        anyhow::bail!("Expected commit message, got: {}", commit_msg.kind);
    }
    
    let R = point_from_hex(&commit_msg.payload)?;
    println!("(Verifier) Received commitment R: {}", commit_msg.payload);

    // 2) Generate and send challenge
    let c = Scalar::random(&mut OsRng);
    let challenge_msg = Message::challenge(&c);
    write_half.write_all((serde_json::to_string(&challenge_msg)? + "\n").as_bytes()).await?;
    println!("(Verifier) Sent challenge c: {}", scalar_to_hex(&c));

    // 3) Receive response from prover
    let Some(line) = reader.next_line().await? else { 
        anyhow::bail!("Connection closed before receiving response") 
    };
    let response_msg: Message = serde_json::from_str(&line)?;
    
    if response_msg.kind != "response" {
        anyhow::bail!("Expected response message, got: {}", response_msg.kind);
    }
    
    let s = scalar_from_hex(&response_msg.payload)?;
    println!("(Verifier) Received response s: {}", response_msg.payload);

    // 4) Verify the proof: check if s*G = R + c*X
    let left_side = RISTRETTO_BASEPOINT_POINT * s;  // s*G
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