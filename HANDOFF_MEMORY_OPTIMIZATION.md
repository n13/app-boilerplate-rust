# Handoff: ML-DSA-87 Memory Optimization for Ledger Hardware Wallets

## Problem Statement

The `qp-rusty-crystals-dilithium` library (ML-DSA-87 / Dilithium5) crashes when
run on Ledger hardware wallets (Stax, Flex, Apex P) due to excessive memory
usage. The app segfaults when `Keypair::generate()` is called during the
GetPubkey APDU handler.

**Target devices**: Ledger Stax, Flex, Apex P (ARM Cortex, `no_std`, custom
allocator)

**Memory constraints**:
- Stack: ~12 KB (device-specific, not well documented)
- Heap: 24,576 bytes maximum (configured in `.cargo/config.toml` via
  `HEAP_SIZE`)
- Total available working memory: roughly 36 KB combined

**Current peak memory**: ~94 KB stack + heap allocations in `keypair()`, ~74 KB+
in `signature()`

## Library Location

**Git repo**: `https://github.com/Quantus-Network/qp-rusty-crystals.git`
**Tag**: `dev-hdwallet-v1.1.0-rc-5`
**Local cargo cache**:
`~/.cargo/git/checkouts/qp-rusty-crystals-82d9197bf54e4d3b/3583d7a/dilithium/`

## Key Parameters (ML-DSA-87 / params.rs)

| Parameter | Value | Notes |
|-----------|-------|-------|
| K | 8 | Rows in matrix A |
| L | 7 | Columns in matrix A |
| N | 256 | Polynomial degree |
| Q | 8,380,417 | Prime modulus |
| PUBLICKEYBYTES | 2,592 | |
| SECRETKEYBYTES | 4,896 | |
| SIGNBYTES | 4,627 | |

## Data Structure Sizes

| Type | Formula | Size (bytes) |
|------|---------|-------------|
| `Poly` | `coeffs: [i32; 256]` | 1,024 |
| `Polyvecl` | `vec: [Poly; L]` = `[Poly; 7]` | 7,168 |
| `Polyveck` | `vec: [Poly; K]` = `[Poly; 8]` | 8,192 |
| Matrix A | `[Polyvecl; K]` = `[Polyvecl; 8]` | 57,344 |

## Root Cause Analysis

### 1. `keypair()` in `sign.rs` (line 21-78)

Stack-allocated locals in this single function:

| Variable | Type | Bytes | Line |
|----------|------|-------|------|
| `mat` | `[Polyvecl; K]` | 57,344 | 43 |
| `s1` | `Polyvecl` | 7,168 | 46 |
| `s2` | `Polyveck` | 8,192 | 49 |
| `s1hat` | `Polyvecl` | 7,168 | 52 |
| `t1` | `Polyveck` | 8,192 | 55 |
| `t0` | `Polyveck` | 8,192 | 62 |
| **Total** | | **96,256** | |

The matrix `mat` alone (57 KB) exceeds the entire available memory.

Additionally, `Keypair::generate()` in `ml_dsa_87.rs` (line 32-43) allocates
`pk: [u8; 2592]` and `sk: [u8; 4896]` on the stack before calling
`sign::keypair()`, adding ~7.5 KB more.

### 2. `signature()` in `sign.rs` (line 300-413)

The signing path has similar issues:

- `prepare_signing_context()` (line 150-181) allocates another full matrix A
  (`[Polyvecl; K]` = 57,344 bytes) at line 177
- `UnpackedSecretKey` struct (line 92-99) holds `Polyveck` + `Polyvecl` +
  `Polyveck` = 23,552 bytes
- The rejection sampling loop in `signature()` allocates multiple Polyvecl and
  Polyveck locals adding ~40 KB more
- A `dummy_output: [u8; SIGNBYTES]` (4,627 bytes) for timing countermeasures

### 3. `verify()` in `sign.rs` (line 424-490)

- Line 432: Another full matrix `mat: [Polyvecl; K]` = 57,344 bytes
- Plus `z: Polyvecl`, `t1: Polyveck`, `w1: Polyveck`, `h: Polyveck` = ~31 KB
- `buf: [u8; K * POLYW1_PACKEDBYTES]` = 1,024 bytes

## Important Note: Existing Stack Demo

The library includes `examples/stack_usage_demo.rs` which claims ML-DSA-87
works with a 4 KB thread stack on desktop. This is because the Rust compiler on
x86_64 with default optimization can reuse stack slots for non-overlapping
lifetimes and may even optimize large arrays to registers or memory-mapped
regions. **This does NOT work on the Ledger ARM target** compiled with
`opt-level = 'z'` (optimize for size), which produces different codegen.

The `test_all_variants_4kb_stack` test in that file passes on desktop but the
same code segfaults on Ledger hardware.

## Proposed Solution: Streaming Matrix Expansion

The core insight is that the matrix A is only ever used for a single
matrix-vector product: `t = A * v`. The full 57 KB matrix doesn't need to exist
simultaneously in memory. Instead, compute the product one row at a time,
generating each polynomial `A[i][j]` on-the-fly.

### Current flow (keypair):

```rust
// sign.rs line 43-56
let mut mat: [Polyvecl; K] = ...;         // 57,344 bytes on stack
polyvec::matrix_expand(&mut mat, &rho);    // Fill entire matrix
let mut t1 = Polyveck::default();
polyvec::matrix_pointwise_montgomery(&mut t1, &mat, &s1hat);  // t1 = A * s1hat
```

### Proposed streaming flow:

```rust
// Compute t1 = A * s1hat row by row, one row at a time
let mut t1 = Polyveck::default();
let mut a_ij = Poly::default();            // 1,024 bytes - reused each iteration
for i in 0..K {
    // t1[i] = sum_j(A[i][j] * s1hat[j])
    let mut acc = Poly::default();         // 1,024 bytes - accumulator
    for j in 0..L {
        // Generate A[i][j] on-the-fly using the same SHAKE128 expansion
        poly::uniform(&mut a_ij, &rho, ((i << 8) + j) as u16);
        // Pointwise multiply and accumulate
        let mut tmp = Poly::default();
        poly::pointwise_montgomery(&mut tmp, &a_ij, &s1hat.vec[j]);
        poly::add_ip(&mut acc, &tmp);
    }
    t1.vec[i] = acc;
}
```

**Peak memory with streaming**: `s1hat` (7,168) + `t1` (8,192) + `a_ij` (1,024)
+ `acc` (1,024) + `tmp` (1,024) = **18,432 bytes** for the matrix operation,
down from 57,344.

### Functions that need the streaming treatment:

1. **`sign::keypair()`** (line 43-56) - matrix expand + matrix_pointwise
2. **`sign::prepare_signing_context()`** (line 177-178) - matrix stored in
   `SigningContext`
3. **`sign::generate_masking_vector_and_commitment()`** (line 254-276) - uses
   `expanded_matrix_a`
4. **`sign::verify()`** (line 432, 463, 466) - matrix expand +
   matrix_pointwise

### Approach for signing (harder case):

In `signature()`, the matrix A is expanded once in `prepare_signing_context()`
and then used potentially multiple times in the rejection sampling loop (each
attempt calls `generate_masking_vector_and_commitment()` which does `w = A * y`).

Options:
- **Option A**: Re-expand A on every signing attempt (re-run SHAKE128 each time).
  This is computationally more expensive but eliminates the 57 KB storage.
  Dilithium's rejection sampling typically succeeds within 4-5 attempts, so this
  is ~4-5x more SHAKE128 work.
- **Option B**: Store the `rho` seed and re-expand each row of A as needed during
  the matrix-vector multiply. Same as Option A but makes the re-expansion
  explicit.
- **Option C**: If heap is available, `Box` the matrix onto the 24 KB heap. But
  57 KB > 24 KB heap, so this doesn't work directly. Could work if the matrix
  is split into chunks, but adds complexity.

**Recommendation**: Option A/B - re-expand from `rho` each time. The SHAKE128
expansion is fast and the alternative (keeping the matrix) is simply impossible
in 24 KB.

## Detailed Memory Budget After Optimization

### keypair() target budget:

| Variable | Type | Bytes |
|----------|------|-------|
| seedbuf, rho, rhoprime, key | byte arrays | ~160 |
| s1 | Polyvecl | 7,168 |
| s2 | Polyveck | 8,192 |
| s1hat | Polyvecl | 7,168 |
| t1 | Polyveck | 8,192 |
| t0 | Polyveck | 8,192 |
| a_ij (reused) | Poly | 1,024 |
| acc (reused) | Poly | 1,024 |
| tmp (reused) | Poly | 1,024 |
| **Total** | | **~42 KB** |

This is still too much for a 12 KB stack. Additional optimizations needed:

### Further stack reduction strategies:

1. **Reuse s1hat and s1**: After computing `s1hat = NTT(s1)`, the original `s1`
   is only needed later for `pack_sk`. Could pack `s1` into `sk` early, then
   reuse the `s1` slot for `t0`.

2. **Sequential computation with packing**: Compute and pack results
   incrementally:
   - Generate s1, compute s1hat = NTT(s1), pack s1 into sk buffer immediately
   - Now s1 slot is free - reuse for s2
   - Generate s2, compute t1 = A*s1hat + s2 (streaming), pack s2 into sk
   - Now s2 slot is free - reuse for t0
   - Compute power2round to get t1, t0
   - Pack everything

3. **Box individual Polyvecl/Polyveck on heap**: If heap has capacity, move some
   of the polynomial vectors to heap. With streaming matrix, we save 57 KB of
   heap need. The remaining vectors could potentially fit:
   - s1hat on heap: 7,168 bytes
   - t1 on heap: 8,192 bytes
   - Total heap: ~15 KB, leaving ~9 KB heap for other allocations
   - Stack would then only have: s1/s2/t0 (sharing slots) + streaming temps

4. **Feature flag**: Add a `constrained` or `embedded` feature flag that enables
   the streaming codepath. The default path remains unchanged for
   desktop/server use where memory is plentiful.

### Aggressive target budget (with slot reuse + Boxing):

Stack:
| Variable | Type | Bytes |
|----------|------|-------|
| seedbuf/rho/rhoprime/key | byte arrays | ~160 |
| poly_slot_1 (reused across s1/s2 components) | Polyvecl | 7,168 |
| a_ij | Poly | 1,024 |
| acc | Poly | 1,024 |
| tmp | Poly | 1,024 |
| **Stack total** | | **~10.4 KB** |

Heap:
| Variable | Type | Bytes |
|----------|------|-------|
| s1hat (NTT domain, needed throughout) | `Box<Polyvecl>` | 7,168 |
| t1 (accumulating result) | `Box<Polyveck>` | 8,192 |
| preimage Vec | Vec<u8> | ~34 |
| **Heap total** | | **~15.4 KB** |

This fits within the 12 KB stack + 24 KB heap budget.

## Implementation Guidance

### File: `dilithium/src/sign.rs`

#### Modifying `keypair()` (line 21-78):

Replace the matrix expansion and multiply at lines 43-56:

```rust
// BEFORE (lines 43-56):
let mut mat: [Polyvecl; K] = array::from_fn(|_| Polyvecl::default());
polyvec::matrix_expand(&mut mat, &rho);
// ... s1, s2, s1hat ...
polyvec::matrix_pointwise_montgomery(&mut t1, &mat, &s1hat);

// AFTER - streaming matrix-vector multiply:
// (mat is never materialized)
streaming_matrix_pointwise_montgomery(&mut t1, &rho, &s1hat);
```

#### New helper function to add (in `polyvec.rs` or `sign.rs`):

```rust
/// Streaming matrix-vector multiply: computes t = A * v
/// where A is expanded on-the-fly from rho, one row at a time.
///
/// Peak additional memory: 3 * Poly = 3,072 bytes (instead of 57,344 for full matrix)
pub fn streaming_matrix_pointwise_montgomery(
    t: &mut Polyveck,
    rho: &[u8],
    v: &Polyvecl,
) {
    let mut a_ij = Poly::default();  // reused each iteration
    for i in 0..K {
        // Compute t[i] = sum_j( A[i][j] * v[j] )
        // First term
        poly::uniform(&mut a_ij, rho, ((i << 8) + 0) as u16);
        poly::pointwise_montgomery(&mut t.vec[i], &a_ij, &v.vec[0]);

        // Accumulate remaining terms
        let mut tmp = Poly::default();
        for j in 1..L {
            poly::uniform(&mut a_ij, rho, ((i << 8) + j) as u16);
            poly::pointwise_montgomery(&mut tmp, &a_ij, &v.vec[j]);
            poly::add_ip(&mut t.vec[i], &tmp);
        }
    }
}
```

#### Modifying `prepare_signing_context()` (line 150-181):

Remove `expanded_matrix_a` from `SigningContext`. Instead, store only `rho` (32
bytes) and re-expand during each signing attempt:

```rust
struct SigningContext {
    // REMOVED: expanded_matrix_a: [Polyvecl; K],  // was 57,344 bytes
    public_seed_rho: [u8; params::SEEDBYTES],       // 32 bytes - expand on demand
    message_hash_mu: [u8; params::CRHBYTES],
    signing_entropy_rho_prime: [u8; params::CRHBYTES],
}
```

Then modify `generate_masking_vector_and_commitment()` (line 254-276) to accept
`rho` instead of `expanded_matrix_a` and use the streaming multiply.

#### Modifying `verify()` (line 424-490):

Same treatment - replace the matrix expansion at line 432/463 with streaming
multiply.

### File: `dilithium/src/polyvec.rs`

Add the `streaming_matrix_pointwise_montgomery()` function here alongside the
existing `matrix_pointwise_montgomery()`.

Consider also adding `streaming_matrix_expand_row()` if you want a more modular
approach:

```rust
/// Expand a single row of matrix A from seed rho
pub fn matrix_expand_row(row: &mut Polyvecl, rho: &[u8], row_index: usize) {
    for j in 0..L {
        poly::uniform(&mut row.vec[j], rho, ((row_index << 8) + j) as u16);
    }
}
```

This approach uses one Polyvecl (7,168 bytes) per row instead of the full matrix
but is simpler than the per-element streaming approach.

### File: `dilithium/src/ml_dsa_87.rs`

#### Modifying `Keypair::generate()` (line 32-43):

Currently allocates `pk: [u8; 2592]` and `sk: [u8; 4896]` on the stack (~7.5
KB). Consider having the caller provide pre-allocated buffers, or using Box:

```rust
pub fn generate(entropy: SensitiveBytes32) -> Keypair {
    let mut pk = alloc::boxed::Box::new([0u8; PUBLICKEYBYTES]);  // heap
    let mut sk = alloc::boxed::Box::new([0u8; SECRETKEYBYTES]);  // heap
    crate::sign::keypair(&mut *pk, &mut *sk, entropy);
    // ... rest unchanged
}
```

### Feature flag approach:

Add to `dilithium/Cargo.toml`:

```toml
[features]
default = []
embedded = []  # Enables streaming matrix operations for constrained memory
```

Then in the code:

```rust
#[cfg(feature = "embedded")]
streaming_matrix_pointwise_montgomery(&mut t1, &rho, &s1hat);

#[cfg(not(feature = "embedded"))]
{
    let mut mat: [Polyvecl; K] = array::from_fn(|_| Polyvecl::default());
    polyvec::matrix_expand(&mut mat, &rho);
    polyvec::matrix_pointwise_montgomery(&mut t1, &mat, &s1hat);
}
```

## Testing Strategy

### 1. Correctness tests (most important)

All existing tests must continue to pass with the streaming implementation:

```bash
cd dilithium
cargo test
```

Key tests to watch:
- `sign::tests::self_verify` - keypair + sign + verify round-trip
- `sign::tests::self_verify_hedged` - hedged signing
- `sign::tests::test_fixed_seed_keypair` - deterministic keypair from seed
- `sign::tests::test_deterministic_signing` - same seed produces same signature
- All tests in `polyvec::tests` and `poly::tests`

### 2. Stack usage verification

Update `examples/stack_usage_demo.rs` to test with smaller stack sizes. The
current minimum is reportedly 4 KB on desktop. With the streaming optimization,
test whether it works with even smaller stacks:

```rust
let stack_sizes = [16, 12, 10, 8, 6, 4, 3, 2];
```

### 3. Cross-verification

Generate a keypair with the original code, save the public key. Generate a
keypair with the streaming code using the same seed. Verify the public keys
match. This is the most critical correctness test.

```rust
#[test]
fn streaming_produces_same_keypair() {
    let seed = SensitiveBytes32::new(&mut [42u8; 32]);
    let mut pk_original = [0u8; PUBLICKEYBYTES];
    let mut sk_original = [0u8; SECRETKEYBYTES];
    keypair_original(&mut pk_original, &mut sk_original, seed.clone());

    let mut pk_streaming = [0u8; PUBLICKEYBYTES];
    let mut sk_streaming = [0u8; SECRETKEYBYTES];
    keypair_streaming(&mut pk_streaming, &mut sk_streaming, seed);

    assert_eq!(pk_original, pk_streaming);
    assert_eq!(sk_original, sk_streaming);
}
```

### 4. Cross-signing verification

Sign with original code, verify with streaming code, and vice versa:

```rust
#[test]
fn cross_sign_verify() {
    // Generate keypair (any method)
    // Sign with original signature()
    // Verify with streaming verify() -> must pass
    // Sign with streaming signature()
    // Verify with original verify() -> must pass
}
```

### 5. Integration test on Ledger emulator

After the library changes, rebuild the Ledger app and test with Speculos
emulator:

```bash
# Inside the Ledger Docker container
# Send GetPubkey APDU to verify keypair generation works
echo "e005000015058000002c80002e32580000000000000000000000" | \
  xxd -r -p | nc localhost 9999 | xxd
```

The BIP32 path `m/44'/189189'/0'/0'/0'` is encoded as:
`05` (5 components) followed by 5 big-endian u32s:
`8000002c` (44') `80002e3258` (189189') `80000000` (0') `80000000` (0')
`80000000` (0')

## Key Functions Reference

| Function | File:Line | What it does | Memory issue |
|----------|-----------|--------------|--------------|
| `keypair()` | sign.rs:21 | Key generation | 57KB matrix on stack |
| `prepare_signing_context()` | sign.rs:150 | Pre-compute for signing | 57KB matrix in struct |
| `generate_masking_vector_and_commitment()` | sign.rs:254 | Per-attempt computation | Uses stored matrix |
| `signature()` | sign.rs:300 | Full signing | Calls above + more locals |
| `verify()` | sign.rs:424 | Signature verification | 57KB matrix on stack |
| `matrix_expand()` | polyvec.rs:32 | Fill matrix A from seed | Called by all above |
| `matrix_pointwise_montgomery()` | polyvec.rs:52 | t = A * v | Requires full matrix |
| `poly::uniform()` | poly.rs:204 | Generate one A[i][j] | 1KB output - this is the key to streaming |
| `Keypair::generate()` | ml_dsa_87.rs:32 | Public API wrapper | 7.5KB pk+sk on stack |
| `SecretKey::sign()` | ml_dsa_87.rs:145 | Public API wrapper | Calls signature() |

## Dependency Information

The library has minimal dependencies:
- `zeroize` (workspace) - for secure memory clearing
- No allocator dependency (uses `alloc` crate directly)
- `#![no_std]` compatible

The library's `alloc` usage (heap allocations):
- `keypair()` line 26: `Vec<u8>` for preimage (~34 bytes)
- `ml_dsa_87.rs`: `SecretKey::sign()` allocates `Vec<u8>` for message with
  context prefix
- `PublicKey::verify()` allocates `Vec<u8>` for message with context prefix
- `vec![0u8; SIGNBYTES]` in `Keypair::generate()` for zeroization

## Summary of Changes Needed

1. Add `streaming_matrix_pointwise_montgomery()` to `polyvec.rs`
2. Modify `keypair()` to use streaming instead of `matrix_expand()` +
   `matrix_pointwise_montgomery()`
3. Modify `SigningContext` to store `rho` instead of `expanded_matrix_a`
4. Modify `generate_masking_vector_and_commitment()` to use streaming multiply
5. Modify `verify()` to use streaming multiply
6. Optionally: Box pk/sk buffers in `Keypair::generate()` and
   `SecretKey::sign()`
7. Optionally: Add feature flag to keep both codepaths
8. Run all existing tests to verify correctness
9. Update `stack_usage_demo.rs` to verify reduced stack requirements

## Risk Assessment

- **Correctness risk**: LOW - the streaming approach computes exactly the same
  mathematical operation. `poly::uniform()` is deterministic given (rho, nonce),
  so generating A[i][j] on-the-fly produces identical polynomials to
  pre-expanding the full matrix.

- **Performance risk**: MODERATE - re-expanding A for each signing attempt adds
  ~K*L = 56 SHAKE128 expansions per attempt. With typical 4-5 rejection sampling
  attempts, this is ~224-280 extra SHAKE128 blocks. On constrained hardware this
  may add noticeable latency but signing is already not time-critical for a
  hardware wallet (user is physically confirming on screen).

- **Timing side-channel risk**: LOW - the streaming approach performs the same
  number of SHAKE128 and polynomial multiply operations regardless of the data.
  The existing timing countermeasures (fixed rejection sampling iterations) are
  preserved.
