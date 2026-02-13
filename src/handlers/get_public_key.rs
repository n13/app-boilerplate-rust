/*****************************************************************************
 *   Ledger App Boilerplate Rust.
 *   (c) 2023 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

use crate::app_ui::address::ui_display_pk;
use crate::utils::{get_address_hash_from_pubkey, get_dilithium_keypair_from_path, Bip32Path};
use crate::AppSW;
use ledger_device_sdk::io::Comm;
use ledger_device_sdk::testing::debug_print;
use qp_rusty_crystals_dilithium::ml_dsa_87::PUBLICKEYBYTES;

/// Handler for GET_PUBLIC_KEY APDU command.
///
/// Derives and returns the Dilithium (ML-DSA-87) public key for a given BIP32 path,
/// optionally displaying the corresponding SS58 address on the device for user verification.
///
/// # Flow
///
/// 1. Parse BIP32 path from APDU data
/// 2. Derive Dilithium keypair via secp256k1 seed → Keypair::generate()
/// 3. If display requested, compute Poseidon address hash and show SS58 address
/// 4. Return the 2592-byte Dilithium public key to the client
///
/// # Response Format
///
/// [pubkey_len_hi (1 byte)] [pubkey_len_lo (1 byte)] [pubkey (2592 bytes)]
pub fn handler_get_public_key(comm: &mut Comm, display: bool) -> Result<(), AppSW> {
    debug_print("=> handler_get_public_key\n");
    let data = comm.get_data().map_err(|_| AppSW::WrongApduLength)?;
    let path: Bip32Path = data.try_into()?;
    debug_print("=> path parsed, deriving keypair\n");

    // Derive Dilithium keypair from BIP32 path
    let keypair = get_dilithium_keypair_from_path(&path)?;
    debug_print("=> keypair derived\n");

    // Display address on device if requested
    if display {
        let address_hash = get_address_hash_from_pubkey(&keypair.public.bytes);
        if !ui_display_pk(&address_hash)? {
            return Err(AppSW::Deny);
        }
    }

    // Return public key length as 2 bytes (big-endian) since it exceeds 255
    let pk_len = PUBLICKEYBYTES as u16;
    comm.append(&pk_len.to_be_bytes());
    comm.append(&keypair.public.bytes);

    Ok(())
}
