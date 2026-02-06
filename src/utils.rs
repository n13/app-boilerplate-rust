use alloc::vec::Vec;

use crate::ml_dsa_ffi::{self, CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES};
use crate::AppSW;
use blake2::digest::{consts::U64, Digest};
use blake2::Blake2b;
use ledger_device_sdk::ecc::{bip32_derive, CurvesId, Secret};
use ledger_device_sdk::testing::debug_print;
use qp_poseidon_core::hash_variable_length_bytes;

/// ML-DSA-87 public key bytes constant (re-exported for compatibility)
pub const PUBLICKEYBYTES: usize = CRYPTO_PUBLICKEYBYTES;

/// BIP32 derivation path stored as a vector of u32 components.
///
/// Each component represents one level in the path (e.g., m/44'/189189'/0'/0'/0' has 5 components).
/// Hardened derivation is indicated by setting the high bit (>= 0x80000000).
#[derive(Default)]
pub struct Bip32Path(Vec<u32>);

impl AsRef<[u32]> for Bip32Path {
    fn as_ref(&self) -> &[u32] {
        &self.0
    }
}

impl TryFrom<&[u8]> for Bip32Path {
    type Error = AppSW;

    /// Constructs a [`Bip32Path`] from APDU-encoded bytes.
    ///
    /// # Format
    ///
    /// - First byte: Number of path components (e.g., 5 for m/44'/189189'/0'/0'/0')
    /// - Remaining bytes: Big-endian u32 components (4 bytes each)
    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        if data.is_empty() || (data[0] as usize * 4 != data.len() - 1) {
            return Err(AppSW::WrongApduLength);
        }

        Ok(Bip32Path(
            data[1..]
                .chunks(4)
                .map(|chunk| u32::from_be_bytes(chunk.try_into().unwrap()))
                .collect(),
        ))
    }
}

/// ML-DSA-87 public key wrapper
pub struct DilithiumPublicKey {
    pub bytes: [u8; CRYPTO_PUBLICKEYBYTES],
}

/// Derive a Dilithium (ML-DSA-87) public key from a BIP32 path.
///
/// Uses the Ledger device's secp256k1 BIP32 derivation to obtain a 32-byte
/// private key, which seeds the RNG for Dilithium keypair generation.
///
/// Note: The C library uses its own internal RNG seeded by the hardware.
/// Currently the BIP32 derivation is performed but the seed is not directly
/// used by the C library. For deterministic keypairs, additional integration
/// would be needed.
///
/// # Arguments
///
/// * `path` - BIP32 derivation path (e.g., m/44'/189189'/0'/0'/0')
///
/// # Returns
///
/// Dilithium public key bytes
pub fn get_dilithium_pubkey_from_path(path: &Bip32Path) -> Result<DilithiumPublicKey, AppSW> {
    debug_print("=> get_dilithium_pubkey_from_path (C lib)\n");

    // Derive BIP32 seed (for future deterministic keypair support)
    let mut tmp = Secret::<64>::new();
    debug_print("=> bip32_derive start\n");
    bip32_derive(CurvesId::Secp256k1, path.as_ref(), tmp.as_mut(), None)
        .map_err(|_| AppSW::KeyDeriveFail)?;
    debug_print("=> bip32_derive done\n");

    // Allocate all buffers on STACK
    // C code uses compact static workspace (tA + union of tB/tC/shake)
    let mut pk = [0u8; CRYPTO_PUBLICKEYBYTES];
    let mut sk = [0u8; CRYPTO_SECRETKEYBYTES];
    
    debug_print("=> crypto_sign_keypair start\n");
    unsafe {
        ml_dsa_ffi::generate_keypair(&mut pk, &mut sk)
            .map_err(|_| AppSW::KeyDeriveFail)?;
    }
    debug_print("=> crypto_sign_keypair done\n");

    // Zero out secret key
    for byte in sk.iter_mut() {
        *byte = 0;
    }

    Ok(DilithiumPublicKey { bytes: pk })
}

/// Compute the 32-byte address hash from a Dilithium public key using Poseidon.
///
/// The Quantus network derives addresses by hashing the full ML-DSA-87 public key
/// with the Poseidon2 hash function over the Goldilocks field.
///
/// # Arguments
///
/// * `pubkey_bytes` - PUBLICKEYBYTES long Dilithium public key
///
/// # Returns
///
/// 32-byte Poseidon hash used as the account ID in SS58 encoding
pub fn get_address_hash_from_pubkey(pubkey_bytes: &[u8; PUBLICKEYBYTES]) -> [u8; 32] {
    debug_print("=> get_address_hash_from_pubkey (poseidon)\n");
    let h = hash_variable_length_bytes(pubkey_bytes);
    debug_print("=> poseidon hash done\n");
    h
}

/// SS58 network prefix for the Quantus network.
const SS58_PREFIX: u16 = 189;

/// Encode a 32-byte account ID as an SS58 address string with Quantus prefix (189).
///
/// # SS58 Format
///
/// For network IDs 64-16383, the prefix uses a 2-byte "canary" encoding:
/// - byte0 = ((value & 0xFC) >> 2) | 0x40
/// - byte1 = (value >> 8) | ((value & 0x03) << 6)
///
/// Full encoding: Base58( prefix_bytes || account_id || checksum )
/// where checksum = first 2 bytes of Blake2b-512("SS58PRE" || prefix_bytes || account_id)
///
/// # Arguments
///
/// * `account_id` - 32-byte address hash (from Poseidon hash of public key)
///
/// # Returns
///
/// SS58-encoded address string
pub fn encode_ss58_address(account_id: &[u8; 32]) -> Result<alloc::string::String, AppSW> {
    debug_print("=> encode_ss58_address\n");
    // Encode the 2-byte prefix for network ID 189
    let prefix_byte0 = ((SS58_PREFIX & 0xFC) >> 2) as u8 | 0x40;
    let prefix_byte1 = (SS58_PREFIX >> 8) as u8 | ((SS58_PREFIX & 0x03) << 6) as u8;
    let prefix_bytes = [prefix_byte0, prefix_byte1];

    // Build the payload: prefix || account_id
    let mut payload = [0u8; 2 + 32]; // 2-byte prefix + 32-byte account
    payload[..2].copy_from_slice(&prefix_bytes);
    payload[2..].copy_from_slice(account_id);

    // Compute checksum: Blake2b-512("SS58PRE" || prefix_bytes || account_id), take first 2 bytes
    let mut hasher = Blake2b::<U64>::new();
    hasher.update(b"SS58PRE");
    hasher.update(&payload);
    let hash = hasher.finalize();
    let checksum = [hash[0], hash[1]];

    // Encode: prefix_bytes || account_id || checksum
    let mut full = [0u8; 2 + 32 + 2]; // 36 bytes total
    full[..34].copy_from_slice(&payload);
    full[34..].copy_from_slice(&checksum);

    Ok(bs58::encode(&full).into_string())
}
