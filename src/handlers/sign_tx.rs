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
use crate::app_ui::sign::ui_display_tx;
use crate::ml_dsa_ffi::CRYPTO_BYTES as SIGNBYTES;
use crate::utils::Bip32Path;
use crate::AppSW;
use alloc::vec::Vec;
use ledger_device_sdk::io::Comm;
use ledger_device_sdk::nbgl::NbglHomeAndSettings;
use ledger_device_sdk::testing::debug_print;

use serde::Deserialize;
use serde_json_core::from_slice;

const MAX_TRANSACTION_LEN: usize = 510;

#[derive(Deserialize)]
pub struct Tx<'a> {
    #[allow(dead_code)]
    nonce: u64,
    pub coin: &'a str,
    pub value: u64,
    #[serde(with = "hex::serde")]
    pub to: [u8; 20],
    pub memo: &'a str,
}

/// Transaction context holding state between APDU chunks.
pub struct TxContext {
    raw_tx: Vec<u8>,
    path: Bip32Path,
    review_finished: bool,
    pub home: NbglHomeAndSettings,
}

impl TxContext {
    pub fn new() -> TxContext {
        TxContext {
            raw_tx: Vec::new(),
            path: Default::default(),
            review_finished: false,
            home: Default::default(),
        }
    }

    pub fn finished(&self) -> bool {
        self.review_finished
    }

    fn reset(&mut self) {
        self.raw_tx.clear();
        self.path = Default::default();
        self.review_finished = false;
    }
}

/// Handler for the Sign Transaction APDU.
///
/// Receives transaction chunks, parses them, and signs with Dilithium (ML-DSA-87).
///
/// # Response Format
///
/// On success, returns:
/// [sig_len (4 bytes BE)] [signature (4627 bytes)] [pubkey (2592 bytes)]
///
/// Total response: 4 + 4627 + 2592 = 7223 bytes
pub fn handler_sign_tx(
    comm: &mut Comm,
    chunk: u8,
    more: bool,
    ctx: &mut TxContext,
) -> Result<(), AppSW> {
    debug_print("=> handler_sign_tx\n");
    let data = comm.get_data().map_err(|_| AppSW::WrongApduLength)?;

    if chunk == 0 {
        debug_print("Chunk 0: Path parsing\n");
        ctx.reset();
        ctx.path = data.try_into()?;
        Ok(())
    } else {
        if ctx.raw_tx.len() + data.len() > MAX_TRANSACTION_LEN {
            return Err(AppSW::TxWrongLength);
        }

        ctx.raw_tx.extend(data);

        if more {
            ctx.review_finished = false;
            Ok(())
        } else {
            debug_print("Last chunk received, parsing tx\n");
            let (tx, _): (Tx, usize) = from_slice(&ctx.raw_tx).map_err(|_| AppSW::TxParsingFail)?;
            debug_print("Tx parsed successfully\n");

            if ui_display_tx(&tx)? {
                ctx.review_finished = true;
                compute_signature_and_append(comm, ctx)
            } else {
                ctx.review_finished = true;
                Err(AppSW::Deny)
            }
        }
    }
}

/// Sign the raw transaction bytes with Dilithium and append signature + pubkey to response.
///
/// TODO: Signing requires the small NTT implementation which is not yet available in the C library.
/// This will be implemented once we port the small NTT functions from m4fstack assembly to pure C.
fn compute_signature_and_append(_comm: &mut Comm, _ctx: &mut TxContext) -> Result<(), AppSW> {
    debug_print("Signing transaction with Dilithium - NOT YET IMPLEMENTED\n");

    // Signing requires the small_ntt functions which are assembly-only in m4fstack
    // and haven't been ported to pure C yet.
    //
    // Future implementation:
    // 1. Port small_ntt_asm_769, small_invntt_asm_769, small_basemul_asm_769 to pure C
    // 2. Call crypto_sign_signature_ctx from ml_dsa_ffi
    // 3. Append signature and public key to response

    Err(AppSW::TxSignFail)
}
