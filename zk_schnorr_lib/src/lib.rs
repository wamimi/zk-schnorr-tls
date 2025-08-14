//! This library provides the core types and utilities for implementing
// ristretto because it provides a clean safe abstraction overthe curve 25519
use curve25519_dalek::ristretto::RistrettoPoint; // reperesents a point on the Curve25519 elliptic curve
use curve25519_dalek::scalar::Scalar; // reperesents a scalar value on the curves field
use hex::{encode as hex_encode, decode as hex_decode}; // to transmit binary data as readabe text
use serde::{Deserialize, Serialize}; // trait fir converting strucys to and from JSON



// Message types exchanged between prover and verifier
#[derive(Serialize, Deserialize, Debug, Clone)] // macro to implement serialization and deserialization for the Message struct, Debug for printing, Clone for duplicating the struct
pub struct Message {
    // the type of message "commit", "challenge", or "response"
    pub kind: String,
    // The payload data as a hex-encoded string
    pub payload: String,
}

impl Message {
    /// Create a new commit message with a point
    pub fn commit(point: &RistrettoPoint) -> Self {
        Self {
            kind: "commit".to_string(),
            payload: point_to_hex(point),
        }
    }

    /// Create a new challenge message with a scalar
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

/// Convert a hex string to a Scalar
/// 
/// This function takes a hex-encoded string and converts it to a Scalar.
/// The `from_bytes_mod_order` ensures the result is valid in our field.
pub fn scalar_from_hex(s: &str) -> Result<Scalar, hex::FromHexError> {
    let bytes = hex_decode(s)?;
    if bytes.len() != 32 {
        return Err(hex::FromHexError::InvalidStringLength);
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(Scalar::from_bytes_mod_order(arr))
}

/// Convert a Scalar to a hex string
pub fn scalar_to_hex(s: &Scalar) -> String {
    hex_encode(s.to_bytes())
}

/// Convert a RistrettoPoint to a hex string
/// 
/// We compress the point to 32 bytes before encoding to hex.
/// This is more efficient than the uncompressed representation.
pub fn point_to_hex(p: &RistrettoPoint) -> String {
    hex_encode(p.compress().to_bytes())
}

/// Convert a hex string to a RistrettoPoint
pub fn point_from_hex(s: &str) -> Result<RistrettoPoint, PointDecodeError> {
    let bytes = hex_decode(s).map_err(PointDecodeError::HexDecode)?;
    if bytes.len() != 32 {
        return Err(PointDecodeError::InvalidLength(bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    
    use curve25519_dalek::ristretto::CompressedRistretto;
    let compressed = CompressedRistretto(arr);
    
    compressed.decompress()
        .ok_or(PointDecodeError::InvalidPoint)
}

/// Errors that can occur when decoding points from hex
#[derive(Debug, thiserror::Error)]
pub enum PointDecodeError {
    #[error("Hex decoding failed: {0}")]
    HexDecode(#[from] hex::FromHexError),
    #[error("Invalid point length: expected 32 bytes, got {0}")]
    InvalidLength(usize),
    #[error("Invalid point: failed to decompress")]
    InvalidPoint,
}