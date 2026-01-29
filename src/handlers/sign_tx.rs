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
use crate::utils::{get_dilithium_keypair_from_path, Bip32Path};
use crate::AppSW;
use alloc::vec::Vec;
use ledger_device_sdk::io::Comm;
use ledger_device_sdk::nbgl::NbglHomeAndSettings;
use ledger_device_sdk::testing::debug_print;

use serde::Deserialize;
use serde_json_core::from_slice;

const MAX_TRANSACTION_LEN: usize = 510;

use ledger_device_sdk::libcall::swap::CreateTxParams;

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
pub struct TxContext<'a> {
    raw_tx: Vec<u8>,
    path: Bip32Path,
    review_finished: bool,
    pub home: NbglHomeAndSettings,
    pub swap_params: Option<&'a CreateTxParams>,
}

impl<'a> TxContext<'a> {
    pub fn new() -> TxContext<'a> {
        TxContext {
            raw_tx: Vec::new(),
            path: Default::default(),
            review_finished: false,
            home: Default::default(),
            swap_params: None,
        }
    }

    pub fn new_with_swap(params: &'a CreateTxParams) -> TxContext<'a> {
        TxContext {
            raw_tx: Vec::new(),
            path: Default::default(),
            review_finished: false,
            home: Default::default(),
            swap_params: Some(params),
        }
    }

    #[allow(dead_code)]
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

            if let Some(params) = ctx.swap_params {
                ctx.review_finished = true;
                if let Err(error) = crate::swap::check_swap_params(params, &tx) {
                    error.append_to_comm(comm);
                    Err(AppSW::SwapFail)
                } else {
                    debug_print("Swap validation success, bypassing UI\n");
                    compute_signature_and_append(comm, ctx)
                }
            } else {
                debug_print("Normal mode, showing UI\n");
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
}

/// Sign the raw transaction bytes with Dilithium and append signature + pubkey to response.
fn compute_signature_and_append(comm: &mut Comm, ctx: &mut TxContext) -> Result<(), AppSW> {
    debug_print("Signing transaction with Dilithium\n");

    // Derive Dilithium keypair from BIP32 path
    let keypair = get_dilithium_keypair_from_path(&ctx.path)?;

    // Sign the raw transaction bytes (deterministic, no hedge, no context)
    let sig = keypair
        .sign(&ctx.raw_tx, None, None)
        .map_err(|_| AppSW::TxSignFail)?;

    // Append signature length as 4 bytes (big-endian) since sig > 255 bytes
    let sig_len = sig.len() as u32;
    comm.append(&sig_len.to_be_bytes());
    // Append signature bytes
    comm.append(&sig);
    // Append public key (receiver needs it for verification and it's part of the Quantus signature format)
    comm.append(&keypair.public.bytes);

    Ok(())
}
