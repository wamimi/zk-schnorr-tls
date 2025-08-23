//! This library provides the core types and utilities for implementing
// ristretto because it provides a clean safe abstraction overthe curve 25519
use curve25519_dalek::ristretto::RistrettoPoint; // reperesents a point on the Curve25519 elliptic curve
use curve25519_dalek::scalar::Scalar; // reperesents a scalar value on the curves field
use hex::{encode as hex_encode, decode as hex_decode}; // to transmit binary data as readabe text
use serde::{Deserialize, Serialize}; // trait for converting structs to and from JSON

// TLS certificate generation
use rcgen::{Certificate, CertificateParams, DistinguishedName};
use rustls::{Certificate as RustlsCertificate, PrivateKey, ServerConfig, ClientConfig, RootCertStore};



// Message types exchanged between prover and verifier
#[derive(Serialize, Deserialize, Debug, Clone)] // macro to implement serialization and deserialization for the Message struct, Debug for printing, Clone for duplicating the struct
pub struct Message {
    // the type of message "commit", "challenge", or "response"
    pub kind: String,
    // The payload data as a hex-encoded string
    pub payload: String,
}

impl Message {
    // new commit message with a point
    pub fn commit(point: &RistrettoPoint) -> Self { // point is a reference to a RistrettoPoint and self is the message type
        Self {
            kind: "commit".to_string(), // string literal to owned string
            payload: point_to_hex(point), // converts the elliptic curve point to a hex string
        }
    }

    // new challenge message with a scalar
    pub fn challenge(scalar: &Scalar) -> Self {
        Self {
            kind: "challenge".to_string(),
            payload: scalar_to_hex(scalar),
        }
    }

    /// Create a new response message with a scalar
    pub fn response(scalar: &Scalar) -> Self {
        Self {
            kind: "response".to_string(),
            payload: scalar_to_hex(scalar),
        }
    }
}

// Convert a hex string to a Scalar
// 
// function takes a hex-encoded string and converts it to a scalar.
// The `from_bytes_mod_order` ensures the result is valid in our field.

pub fn scalar_from_hex(s: &str) -> Result<Scalar, hex::FromHexError> { // s is a reference to a string
    let bytes = hex_decode(s)?; // decode the hex string into bytes
    if bytes.len() != 32 { // check if the length of the bytes is 32
        return Err(hex::FromHexError::InvalidStringLength); // return an error if the length is not 32
    }
    let mut arr = [0u8; 32]; // create an array of 32 bytes
    arr.copy_from_slice(&bytes); // copy the bytes into the array from the vec
    Ok(Scalar::from_bytes_mod_order(arr)) // convert the array to a scalar reducing modulo the curve order
}

//  Convert a Scalar to a hex string
pub fn scalar_to_hex(s: &Scalar) -> String { // s is a reference to a scalar
    hex_encode(s.to_bytes()) // convert the scalar to bytes and then encode the bytes to a hex string
}

// Convert a RistrettoPoint to a hex string
// 
// compress the point to 32 bytes before encoding to hex.
// This is more efficient than the uncompressed representation.
pub fn point_to_hex(p: &RistrettoPoint) -> String {
    hex_encode(p.compress().to_bytes())
} 

/// Convert a hex string to a RistrettoPoint
pub fn point_from_hex(s: &str) -> Result<RistrettoPoint, PointDecodeError> { // s is a reference to a string
    let bytes = hex_decode(s).map_err(PointDecodeError::HexDecode)?; // decode the hex string into bytes
    if bytes.len() != 32 { // check if the length of the bytes is 32
        return Err(PointDecodeError::InvalidLength(bytes.len())); // return an error if the length is not 32
    }
    let mut arr = [0u8; 32]; // create an array of 32 bytes where each element is 0
    arr.copy_from_slice(&bytes); // copy the bytes into the array from the vec
    
    use curve25519_dalek::ristretto::CompressedRistretto; // import the CompressedRistretto type
    let compressed = CompressedRistretto(arr); // create a compressed Ristretto point from the array
    
    compressed.decompress() // decompress the point returns Option
        .ok_or(PointDecodeError::InvalidPoint) // return an error if the point is invalid converts option to result 
}

/// Errors that can occur when decoding points from hex
#[derive(Debug, thiserror::Error)]
pub enum PointDecodeError {
    #[error("Hex decoding failed: {0}")] //defines error message format
    HexDecode(#[from] hex::FromHexError), // automatically convert the hex::FromHexError to PointDecodeError
    #[error("Invalid point length: expected 32 bytes, got {0}")] // defines error message format 0 is the placeholder for the first field variable
    InvalidLength(usize),
    #[error("Invalid point: failed to decompress")] // defines error message format
    InvalidPoint,
}

// TLS Certificate Management
// =========================

/// Errors that can occur during TLS certificate operations
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("Certificate generation failed: {0}")]
    CertificateGeneration(#[from] rcgen::RcgenError),
    #[error("TLS configuration failed: {0}")]
    TlsConfig(#[from] rustls::Error),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Generated TLS certificate and private key pair
pub struct TlsCertificate {
    pub certificate: Certificate,
    pub cert_der: Vec<u8>,
    pub private_key_der: Vec<u8>,
}

/// Generate a self-signed certificate for development use
/// 
/// This creates a certificate valid for 'localhost' and '127.0.0.1'
/// which is perfect for our local development and testing.
/// 
/// # Returns
/// A `TlsCertificate` containing both the certificate and private key
/// in DER format, ready to be used with rustls.
pub fn generate_self_signed_cert() -> Result<TlsCertificate, TlsError> {
    // Set up certificate parameters
    let mut params = CertificateParams::new(vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
    ]);
    
    // Set certificate details
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        "ZK Schnorr TLS Demo"
    );
    params.distinguished_name.push(
        rcgen::DnType::OrganizationName,
        "Zero Knowledge Demo"
    );
    
    // Generate the certificate
    let certificate = Certificate::from_params(params)?;
    
    // Get DER-encoded certificate and private key
    let cert_der = certificate.serialize_der()?;
    let private_key_der = certificate.serialize_private_key_der();
    
    println!("📜 Generated self-signed TLS certificate for localhost");
    println!("   Valid for: localhost, 127.0.0.1");
    println!("   Issuer: ZK Schnorr TLS Demo");
    
    Ok(TlsCertificate {
        certificate,
        cert_der,
        private_key_der,
    })
}

/// Create a TLS server configuration from a certificate
/// 
/// This sets up the server-side TLS configuration that will:
/// - Use the provided certificate for authentication
/// - Support modern TLS versions (1.2 and 1.3)
/// - Use secure cipher suites
/// - Not require client certificates (server-only authentication)
pub fn create_server_config(tls_cert: &TlsCertificate) -> Result<ServerConfig, TlsError> {
    let cert = RustlsCertificate(tls_cert.cert_der.clone());
    let private_key = PrivateKey(tls_cert.private_key_der.clone());
    
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(vec![cert], private_key)?;
    
    println!("🔒 Created TLS server configuration");
    println!("   Mode: Server-only authentication (no client certs required)");
    
    Ok(config)
}

/// Create a TLS client configuration that accepts our self-signed certificate
/// 
/// For development, we need to explicitly trust our self-signed certificate
/// since it won't be signed by a standard Certificate Authority.
/// 
/// # Security Note
/// This configuration accepts ANY certificate without validation!
/// This is ONLY safe for development/demo purposes on localhost.
/// Production code should use proper certificate validation.
pub fn create_client_config(server_cert: &TlsCertificate) -> Result<ClientConfig, TlsError> {
    let mut root_store = RootCertStore::empty();
    
    // Add our self-signed certificate as a trusted root
    // This is needed because our cert isn't signed by a standard CA
    let cert = RustlsCertificate(server_cert.cert_der.clone());
    root_store.add(&cert)?;
    
    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    
    println!("🔒 Created TLS client configuration");
    println!("   Mode: Accept self-signed certificate for localhost");
    println!("   ⚠️  Development only - not for production!");
    
    Ok(config)
}