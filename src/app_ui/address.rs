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

use crate::utils::encode_ss58_address;
use crate::AppSW;

use ledger_device_sdk::include_gif;
use ledger_device_sdk::nbgl::{NbglAddressReview, NbglGlyph};

/// Display an SS58-encoded Quantus address on the device for user verification.
///
/// Takes a 32-byte address hash (Poseidon hash of Dilithium public key),
/// encodes it as SS58 with prefix 189, and displays it on screen with a QR code.
/// NBGL on Stax/Flex/Apex P renders QR codes automatically for address review.
pub fn ui_display_pk(address_hash: &[u8; 32]) -> Result<bool, AppSW> {
    let ss58_addr = encode_ss58_address(address_hash)?;

    #[cfg(target_os = "apex_p")]
    const FERRIS: NbglGlyph = NbglGlyph::from_include(include_gif!("glyphs/crab_48x48.png", NBGL));
    #[cfg(any(target_os = "stax", target_os = "flex"))]
    const FERRIS: NbglGlyph = NbglGlyph::from_include(include_gif!("glyphs/crab_64x64.gif", NBGL));

    Ok(NbglAddressReview::new()
        .glyph(&FERRIS)
        .review_title("Verify Quantus address")
        .show(&ss58_addr))
}
