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
use proof::gen::GetProofResult;
use starknet_crypto::{get_public_key, rfc6979_generate_k, sign, verify, FieldElement};

use crate::proof::gen::{Address, Felt, StorageKey};

fn main() {
    let proof: GetProofResult = serde_json::from_str(
        r#"{
        "class_commitment": "0x1673962e8f2e850afc1f172e1738578a334384553c84ab6427d1fdef2a3966c",
        "contract_data": {
          "class_hash": "0x7f3777c99f3700505ea966676aac4a0d692c2a9f5e667f4c606b51ca1dd3420",
          "contract_state_hash_version": "0x0",
          "nonce": "0x0",
          "root": "0x37f7706746f1494c842a6acf04f66fdc00129d3188c1c6ac6ab51aa8aaa2a86",
          "storage_proofs": [
            [
              {
                "binary": {
                  "left": "0x7b820e7574d00f9c294d687a09d51135ef407d6227b0657059aae312eb7ca9d",
                  "right": "0x7096b1e752b485f4cbe84960327aab728b71923e11be89d6426054e77ed9da6"
                }
              },
              {
                "binary": {
                  "left": "0x181ffc4e4300cd855d8f170c58a5784054ef54504fa421447abea99b0185c56",
                  "right": "0x49a0d7397b9594894af5b2c34019ecd9f18c900d6ba42d789c6dc236ed8aa48"
                }
              },
              {
                "binary": {
                  "left": "0x1c05b43d914a8f74e23b3dad5abbaca993b223fe7c5d1bfee51d3f4be7e1efb",
                  "right": "0x58619aa9668288a56be39292e20478f9554d3cddc5d345381ac65035b9fd2ea"
                }
              },
              {
                "binary": {
                  "left": "0x44cb87b70edea7d7d8cb5d610f23f52619dfe314483fe6e28e73f0e967169fd",
                  "right": "0x27f9d7ba1ce7ce63441785f74bec772ab1e7abbf46c9d400c84dc304d3dcd91"
                }
              },
              {
                "binary": {
                  "left": "0x1ea69d5c5d986d6e933363b9ee4aa4f68675bed114fc43afac0997456c1c202",
                  "right": "0x586d6a6e276f5b3c6ea92034de5473823d72236942fe147d00c0642eadb0947"
                }
              },
              {
                "binary": {
                  "left": "0x530ef336c357d1f4320cd8d69e65bc5880322ec8e49ea43a5cdfeeb0d178b94",
                  "right": "0x2aad33457701016e5b3cb596a73ceae56a7f8a171b76560ad6ce1003744a5c8"
                }
              },
              {
                "binary": {
                  "left": "0xbc2e51694212be5f6561cc3ec8bbc0181c551d4fed140a21779db98e6ab757",
                  "right": "0x1344c65230e84851873c1f0213e6b524de4f8f2ec9835f9c211c7436419639d"
                }
              },
              {
                "binary": {
                  "left": "0x3b51a002c43411bbf40b11ab562da513e56a70d44b33e9ec183696d9e36b107",
                  "right": "0x5f87538e5f01cdaa1780b748f5b217d493a6cb0344305442852f8c51aa78d7d"
                }
              },
              {
                "binary": {
                  "left": "0x50a12d59b11c574b42d585af144de267c08292f67b5843406530415eaa6a76b",
                  "right": "0x3639f9f6c88d9bd6125bd20d8abae5b048460ab1c17e8030bce959f636f9bd2"
                }
              },
              {
                "binary": {
                  "left": "0x56a690f971b0f6fadd8868277a1cbc7827e2a0707d9ddb2f0735f1592688c4c",
                  "right": "0x425a2b12a2ffa7f43fce77a9a3c05f5dc03d02afa2d02c1f54b6a2a0092ffe6"
                }
              },
              {
                "binary": {
                  "left": "0x6cedb61f3567fcde015fa22e5c6554656e9d9d0a2967d1a2a6cdb4a0b47de2d",
                  "right": "0x4efcfaed1f981d5ece715de56440e4c7aa46cac3c750f1ae29a4b099a6d6d52"
                }
              },
              {
                "binary": {
                  "left": "0x1c7a1d471e2653229a62f0ee33d3ea648beec09fa0b5b4bd3e6525c2bd1540d",
                  "right": "0x4deffa4097370268099da73b7ae82117988fba973966e86131061a328debfd5"
                }
              },
              {
                "binary": {
                  "left": "0x7af34eff82d8761224e7e9cc1149340f92429ee14dd5f19dada94ffdbf5aa08",
                  "right": "0x13a442c12902794f769043b6331b709ac330d0a97f7e54cf57b9d709ab0d16e"
                }
              },
              {
                "binary": {
                  "left": "0x5ac050fdf20970745c65cc1d72b79ef8899ab50a9159c29c91dbf657322ee94",
                  "right": "0x3d64c12d05ea162ee236776dcb13f87304ea865e51818e80397d16aa6c48ffe"
                }
              },
              {
                "binary": {
                  "left": "0x1a487e6cdb9eec5e5eb3f0a56c0cfeca3245579b11ae64a6ac1c37baa710b88",
                  "right": "0x66bcda89bf3c1e26f5383e2c28f7c306124e4c8f3fcc6bc5989dca64c15d80c"
                }
              },
              {
                "binary": {
                  "left": "0xb1ab5140e10d2313a50186fa32deb0d422e672c0c833c8c6bd354adf1fe75e",
                  "right": "0x18d34f712fc79f8b9808cb8332c4bd3f431671d58f721242d01f20929db0963"
                }
              },
              {
                "binary": {
                  "left": "0x6a1676382cdd2ce50cc7df6cbe6da956be9e7ac3afd0c48af60543e73325b5e",
                  "right": "0x7a5301419c08311e4fbc97dd268acd429d81120e85a87dff15e3a3738ad46fe"
                }
              },
              {
                "binary": {
                  "left": "0x1ada0c8ce310e5263b326a0bf26544c49e436513d5d6895613873828ed119a",
                  "right": "0x1e8e03dc68473dff217ec809e5fa97e209014920c632f37fb6f0ae93ec8a54b"
                }
              },
              {
                "binary": {
                  "left": "0x23aa10272fb7861c7c0b48ec9ff319f4b3334f21aa8555821a25d4e75b4f794",
                  "right": "0x5e3ebb31a5d43d9825bc9e369c2ef979aa763c1f059d1c5f171ed4b9524ae6a"
                }
              },
              {
                "binary": {
                  "left": "0x61a4640ad8b3a5b765feee614fa0a63ed5808b5a183744e3b3752cb1656ae1f",
                  "right": "0x4e1a0bb094efdc54a2b7ae65c0916309d195d8487495d5af3347467c9b7fed9"
                }
              },
              {
                "binary": {
                  "left": "0x36ed7628e6e6f75b9457a40702313ab25b43dd8929693441738dfc200152b58",
                  "right": "0x9edec868db73e8db4b0070ae5d245641837a648b805bd7672c282fd290b430"
                }
              },
              {
                "binary": {
                  "left": "0x208d7bb6f0be37943672ecab45511ade56739c592bb1ae85be99c2e4de967c8",
                  "right": "0x587cd3f50e73790aeb979de562b019c9480b32ae7bdb3c3f702fe48c17cfd07"
                }
              },
              {
                "binary": {
                  "left": "0xd45a3e93465df32f7d37f0002b076422689d6e8d64c5fff9c50c0a3ce4245f",
                  "right": "0x5dab73cf75dd6723a3f921ef9cf74800d0081192c993da3f913c07f8849f3b2"
                }
              },
              {
                "edge": {
                  "child": "0x4214328be9b6eb2a658d6085839bbeb17c5532aeef582197385b783610f2606",
                  "path": {
                    "len": 1,
                    "value": "0x0"
                  }
                }
              },
              {
                "binary": {
                  "left": "0x59975c0999114565fd31f4b30da72bbf36d7c79c4ae7856ef6fddfa6fb7c90e",
                  "right": "0x196dee6f9427a6409f8a4835f260752f2ab7a48505f88f379dae9fba60f16b4"
                }
              },
              {
                "edge": {
                  "child": "0x1c09a68b28b1d074c933ed6e1d6e20d85bd808b170f53f6ce7afd7c2f1075c7",
                  "path": {
                    "len": 1,
                    "value": "0x0"
                  }
                }
              },
              {
                "binary": {
                  "left": "0x4c4daa41c1b7e8f577518fcc546e7d11c4a7fb4a6ebe50cd58c6ce8ea186a3c",
                  "right": "0x5febe45f5b17536c4273492b3700b2f923a8ecb865a35a90517306a18b8af16"
                }
              },
              {
                "edge": {
                  "child": "0x4ee9c11468906",
                  "path": {
                    "len": 224,
                    "value": "0x6f9582175d3219f1ac8f974b7960f2edfc8bc03197718dc8967ba1ab"
                  }
                }
              }
            ]
          ]
        },
        "contract_proof": [
          {
            "binary": {
              "left": "0x34f28130531690a28a91086e38142ab7f8bd71e42ecca08418cc29038340b13",
              "right": "0x33307b404165471d935a47883e91a30dec44570d1888f46c4a7a11e0e15f868"
            }
          },
          {
            "binary": {
              "left": "0x660018ffb4e6c8d1918fbba33bfb5348c3c19cb2130ff1cf97b0774c6d8bc74",
              "right": "0x6aee1e40594bf3895ea13d1535efedb3b3b5fd89b6c430f0618119276919e14"
            }
          },
          {
            "binary": {
              "left": "0x2852e84cfb475f037435a0848e742ee13ce4092e8e26f4a8fac1aeaa46f42e",
              "right": "0x6a19c7ec7a009221108629ded9336278d428c6db1e1c6531e7ecbfcba1c452b"
            }
          },
          {
            "binary": {
              "left": "0x348e95e9f72ebc205c50c89fb7911b1c5cda9c1aedc0c950eaea1d92f8df9f",
              "right": "0x7e13277238ec4c56e984f542256e98799741257209d7886857a050aeecac"
            }
          },
          {
            "binary": {
              "left": "0x4d8ae01909a578d848b4f14b22e07d2b3edee815c86eb5719286b4b31db51bb",
              "right": "0x68f228cb650b31dc4e72e2819b453e54a346bbcfc220d3c8e68fa496e966b44"
            }
          },
          {
            "binary": {
              "left": "0x232628a758a51eaf0f6376936adabcd181d475cd4ea2b35cdd17c1b3ab6b638",
              "right": "0x964c01bd29fcc401d16a0220665dca31365ef285370b269ea22efa8328f596"
            }
          },
          {
            "binary": {
              "left": "0x73d3c0dafe2c8994f12916242d1980a4fa922b5b690dee058b817e5a5eedae3",
              "right": "0x25f66bc18d7b2254a481b3a5326ed7e3915dc595337df34eb868b5001a18c08"
            }
          },
          {
            "binary": {
              "left": "0x2689cd1cae8c8aa9df476cdafa6fd1604ad8aafc6307ee9f6e79510c23eee83",
              "right": "0x7c840a030d20eef04b07ba5dc8e9f08ba73db4cfd8d27db135c9f6d5a58a197"
            }
          },
          {
            "binary": {
              "left": "0x7f7a2c1542d21c7921aebcfb42f664dacc6197ec65d6d345537895fdeb03132",
              "right": "0x6d9983b538dae06b391d7c4efe9c06cb87b54d96cdf144e3be358aebc7856b"
            }
          },
          {
            "binary": {
              "left": "0x68884927555e580eea6ffaede222356802e50253e185d92bae74a770aedd367",
              "right": "0x4ff10b676e32df81d760dc6f5cf4550c0aa546289f9629c8fb2228eda828f97"
            }
          },
          {
            "binary": {
              "left": "0x541a3a54fd08a2425e5e8cc8ae16eae738f0ab8506db18684f38b9138fbc902",
              "right": "0x6c4d9f0ee7d4699541c12716b9b4f31379c929a810b6734a58342ad70a216de"
            }
          },
          {
            "binary": {
              "left": "0x263db8dd152690e2661afa610fecd2418a929e161e3563141cfc7712826ebea",
              "right": "0x3633cea99dac6e9ca32581575f9041e5b97cb96b7d98cdffd38a4e85b2784aa"
            }
          },
          {
            "binary": {
              "left": "0x2b79b190d81b42f00d4628af8cbe1bdcba08249fdd69ae140c095197d1455b",
              "right": "0x6935dac97954baf18dd19a691aa5910d1377a7f184533c187068fab33cb4cd5"
            }
          },
          {
            "binary": {
              "left": "0x6476da70779030bec536fdc0b85bffe8005822c7df3f70be472f852fc6ed1ca",
              "right": "0x5e5e45038b10012e3d07627851d7c56304099da4027bf4ec83ccfbccb8018fe"
            }
          },
          {
            "binary": {
              "left": "0x3b52f832acda4816dbb11b4edfc45551d2dd454262d5458ae19b22a41527c86",
              "right": "0x508309ec91a0fb2a5e3a376237909e11d5213440c9f48347c7e2c896191ea64"
            }
          },
          {
            "binary": {
              "left": "0x125aa1fbdb2ee69d5d7dfad333a2cdef0c2aec2f870635f009e81366373cd7d",
              "right": "0x6a00dcb34d054a42ef04ceb1b1abc9013528a2d005c4e0c853a627eb62570fb"
            }
          },
          {
            "binary": {
              "left": "0x2bd2adcb4b5c81c1e49b33cffd54c966f6c1a0be7f0cee1c94c87f5237c595f",
              "right": "0x74ea7cf6655f317ee78a1775945029c03efe949a015fc583e57f8baac75127f"
            }
          },
          {
            "binary": {
              "left": "0xe0c3544d8b7c6c3adda0da5f6baae541ae9f82058535cd1a73f3eea954db46",
              "right": "0x15dbd6d02fa338bb4adca2d1b2088fe5017d83a5b987dbfd725003988d3fe7c"
            }
          },
          {
            "binary": {
              "left": "0x4db024541f765d278810d91420a7164666f358ca640e843ecf1a2552e4645e4",
              "right": "0x2be6ee9ba3ba151dff91cb14b754781670770f7705f6b627d368e14de9048fe"
            }
          },
          {
            "binary": {
              "left": "0x390cb8b703d89025c3f076a3b2aa11e9be5ad39a4b6b1acada68bfc147fa436",
              "right": "0x38f898a0ddbb686820f59f32a134d00f2e7e14cd9c18ce84739e62485b53f08"
            }
          },
          {
            "binary": {
              "left": "0x77f1d27e4b5a24977196f645c3242fd12fd20bf88c821ffc928423db183c87f",
              "right": "0x5cc4f6c766835754642bfb5df2ef0827211aa5ec8ee7fcd43b097e6acb14669"
            }
          },
          {
            "binary": {
              "left": "0x5fae50294399f20a342074c7f01fdc0a3adc9313c45149e6233887461992c71",
              "right": "0x480b4b439ac69e7144b6ffbeb6ce04c0e3093a6ee9e008172261da33fbb176d"
            }
          },
          {
            "edge": {
              "child": "0x6048155d3f8efaddff20f7b5efc0e07d63899f08dd9f3bd4df8e6b8f634fa15",
              "path": {
                "len": 229,
                "value": "0x170d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7"
              }
            }
          }
        ],
        "state_commitment": "0x6fa3da35851f94a792cebb398d233f2c377951c20ea0c4a26f27431915f9919"
      }"#,
    )
    .unwrap();

    //verify storage proof
    let result = proof.verify(
        Felt::try_new("0x6fa3da35851f94a792cebb398d233f2c377951c20ea0c4a26f27431915f9919").unwrap(),
        Address(
            Felt::try_new("0x49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7")
                .unwrap(),
        ),
        StorageKey::try_new("0x02c401056f9582175d3219f1ac8f974b7960f2edfc8bc03197718dc8967ba1ab")
            .unwrap(),
        Felt::try_new("0x4ee9c11468906").unwrap(),
    );

    if let Err(e) = &result {
        println!("Error: {:?}", e);
    } else {
        println!("Storage proof verified successfully");
    }

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
