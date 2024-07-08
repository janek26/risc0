// Copyright 2024 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#[path = "../proof.rs"]
pub mod proof;
use starknet_crypto::{get_public_key, rfc6979_generate_k, sign, verify, FieldElement};

fn main() {
    // Generate a random secp256k1 keypair and sign the message.
    let pk = FieldElement::from_hex_be("0x123").unwrap();
    let message_hash = FieldElement::from_hex_be("0x456").unwrap();
    let seed = FieldElement::from_hex_be("0x00").ok();
    let k = rfc6979_generate_k(&message_hash, &pk, seed.as_ref());
    let signature = sign(&pk, &message_hash, &k).unwrap();
    let pubkey = get_public_key(&pk);

    // log msgHash, sigR, sigS and pubKey as hex
    println!("msgHash: {:?}", message_hash);
    println!("seed: {:?}", seed);
    println!("sigR: 0x{:?}", signature.r);
    println!("sigS: 0x{:?}", signature.s);
    println!("pubKey X: 0x{:?}", pubkey);

    // verify signature with x
    assert!(verify(&pubkey, &message_hash, &signature.r, &signature.s).unwrap());

    println!("Signature verified successfully");
}
