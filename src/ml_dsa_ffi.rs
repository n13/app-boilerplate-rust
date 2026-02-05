// FFI bindings to the ML-DSA C library (m4fstack implementation)
// This provides low-heap-memory Dilithium (ML-DSA-87) operations

// ML-DSA-87 (Dilithium mode 5) constants
pub const CRYPTO_PUBLICKEYBYTES: usize = 2592;  // 32 + 8*320
pub const CRYPTO_SECRETKEYBYTES: usize = 4896;  // 2*32 + 64 + 7*96 + 8*96 + 8*416
pub const CRYPTO_BYTES: usize = 4627;           // 64 + 7*640 + 83

extern "C" {
    /// Generate a keypair
    /// Returns 0 on success
    pub fn crypto_sign_keypair(pk: *mut u8, sk: *mut u8) -> i32;

    /// Sign a message with context
    /// Returns 0 on success, -1 if context too long
    pub fn crypto_sign_signature_ctx(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        ctx: *const u8,
        ctxlen: usize,
        sk: *const u8,
    ) -> i32;

    /// Verify a signature with context
    /// Returns 0 if valid, non-zero otherwise
    pub fn crypto_sign_verify_ctx(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        ctx: *const u8,
        ctxlen: usize,
        pk: *const u8,
    ) -> i32;
}

/// Generate an ML-DSA-87 keypair
///
/// # Safety
/// Caller must provide properly sized buffers:
/// - pk: CRYPTO_PUBLICKEYBYTES (2592)
/// - sk: CRYPTO_SECRETKEYBYTES (4896)
pub unsafe fn generate_keypair(pk: &mut [u8], sk: &mut [u8]) -> Result<(), &'static str> {
    if pk.len() < CRYPTO_PUBLICKEYBYTES {
        return Err("public key buffer too small");
    }
    if sk.len() < CRYPTO_SECRETKEYBYTES {
        return Err("secret key buffer too small");
    }

    let result = crypto_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());
    if result == 0 {
        Ok(())
    } else {
        Err("keypair generation failed")
    }
}

/// Sign a message
///
/// # Safety
/// Caller must provide:
/// - sig: buffer of at least CRYPTO_BYTES
/// - sk: valid secret key of CRYPTO_SECRETKEYBYTES
pub unsafe fn sign(
    sig: &mut [u8],
    message: &[u8],
    sk: &[u8],
) -> Result<usize, &'static str> {
    if sig.len() < CRYPTO_BYTES {
        return Err("signature buffer too small");
    }
    if sk.len() < CRYPTO_SECRETKEYBYTES {
        return Err("secret key too small");
    }

    let mut siglen: usize = 0;
    let result = crypto_sign_signature_ctx(
        sig.as_mut_ptr(),
        &mut siglen,
        message.as_ptr(),
        message.len(),
        core::ptr::null(),
        0,
        sk.as_ptr(),
    );

    if result == 0 {
        Ok(siglen)
    } else {
        Err("signing failed")
    }
}

/// Verify a signature
///
/// # Safety
/// Caller must provide:
/// - pk: valid public key of CRYPTO_PUBLICKEYBYTES
pub unsafe fn verify(
    sig: &[u8],
    message: &[u8],
    pk: &[u8],
) -> Result<bool, &'static str> {
    if pk.len() < CRYPTO_PUBLICKEYBYTES {
        return Err("public key too small");
    }

    let result = crypto_sign_verify_ctx(
        sig.as_ptr(),
        sig.len(),
        message.as_ptr(),
        message.len(),
        core::ptr::null(),
        0,
        pk.as_ptr(),
    );

    Ok(result == 0)
}
