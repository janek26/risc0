use iamgroot::jsonrpc;
use starknet_crypto::{pedersen_hash, poseidon_hash_many, FieldElement};

#[path = "./gen.rs"]
pub mod gen;
use gen::{
    Address, BinaryNode, BinaryNodeBinary, ContractData, EdgeNode, EdgeNodeEdge, Felt,
    GetProofResult, Node, StorageKey,
};

#[path = "./utils.rs"]
pub mod utils;
use utils::{felt_from_bits, felt_to_bits};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Left,
    Right,
}

impl From<bool> for Direction {
    fn from(flag: bool) -> Self {
        if flag {
            Self::Right
        } else {
            Self::Left
        }
    }
}

impl GetProofResult {
    pub fn verify(
        &self,
        global_root: Felt,
        contract_address: Address,
        key: StorageKey,
        value: Felt,
    ) -> Result<(), jsonrpc::Error> {
        let contract_data = self.contract_data.as_ref().ok_or(jsonrpc::Error::new(
            -32700,
            "No contract data found".to_string(),
        ))?;
        self.verify_storage_proofs(contract_data, key, value)?;
        self.verify_contract_proof(contract_data, global_root, contract_address)
    }

    fn verify_storage_proofs(
        &self,
        contract_data: &ContractData,
        key: StorageKey,
        value: Felt,
    ) -> Result<(), jsonrpc::Error> {
        let root = &contract_data.root;
        let storage_proofs = &contract_data
            .storage_proofs
            .as_ref()
            .ok_or(jsonrpc::Error::new(
                -32700,
                "No storage proof found".to_string(),
            ))?[0];

        match Self::parse_proof(key.as_ref(), value, storage_proofs)? {
            Some(computed_root) if computed_root.as_ref() == root.as_ref() => Ok(()),
            Some(computed_root) => Err(jsonrpc::Error::new(
                -32700,
                format!(
                    "Proof invalid:\nprovided-root -> {}\ncomputed-root -> {}\n",
                    root.as_ref(),
                    computed_root.as_ref()
                ),
            )),
            None => Err(jsonrpc::Error::new(
                -32700,
                format!("Proof invalid for root -> {}\n", root.as_ref()),
            )),
        }
    }

    fn verify_contract_proof(
        &self,
        contract_data: &ContractData,
        global_root: Felt,
        contract_address: Address,
    ) -> Result<(), jsonrpc::Error> {
        let state_hash = Self::calculate_contract_state_hash(contract_data)?;

        match Self::parse_proof(
            contract_address.0.as_ref(),
            state_hash,
            &self.contract_proof,
        )? {
            Some(storage_commitment) => {
                let class_commitment = self.class_commitment.as_ref().ok_or(
                    jsonrpc::Error::new(-32700, "No class commitment".to_string()),
                )?;
                let parsed_global_root = Self::calculate_global_root(
                    class_commitment,
                    storage_commitment,
                )
                .map_err(|_| {
                    jsonrpc::Error::new(-32700, "Failed to calculate global root".to_string())
                })?;
                let state_commitment = self.state_commitment.as_ref().ok_or(
                    jsonrpc::Error::new(-32700, "No state commitment".to_string()),
                )?;
                if state_commitment.as_ref() == parsed_global_root.as_ref()
                    && global_root.as_ref() == parsed_global_root.as_ref()
                {
                    Ok(())
                } else {
                    Err(jsonrpc::Error::new(
                        -32700,
                        format!("Proof invalid:\nstate commitment -> {}\nparsed global root -> {}\n global root -> {}", 
                        state_commitment.as_ref(), parsed_global_root.as_ref(), global_root.as_ref())
                    ))
                }
            }
            None => Err(jsonrpc::Error::new(
                -32700,
                format!(
                    "Could not parse global root for root: {}",
                    global_root.as_ref()
                ),
            )),
        }
    }

    fn calculate_contract_state_hash(contract_data: &ContractData) -> Result<Felt, jsonrpc::Error> {
        // The contract state hash is defined as H(H(H(hash, root), nonce), CONTRACT_STATE_HASH_VERSION)
        const CONTRACT_STATE_HASH_VERSION: FieldElement = FieldElement::ZERO;
        let hash = pedersen_hash(
            &FieldElement::from_hex_be(contract_data.class_hash.as_ref()).map_err(|_| {
                jsonrpc::Error::new(-32701, "Failed to create Field Element".to_string())
            })?,
            &FieldElement::from_hex_be(contract_data.root.as_ref()).map_err(|_| {
                jsonrpc::Error::new(-32701, "Failed to create Field Element".to_string())
            })?,
        );
        let hash = pedersen_hash(
            &hash,
            &FieldElement::from_hex_be(contract_data.nonce.as_ref()).map_err(|_| {
                jsonrpc::Error::new(-32701, "Failed to create Field Element".to_string())
            })?,
        );
        let hash = pedersen_hash(&hash, &CONTRACT_STATE_HASH_VERSION);
        Felt::try_new(&format!("0x{:x}", hash))
            .map_err(|_| jsonrpc::Error::new(-32701, "Failed to create Field Element".to_string()))
    }

    fn calculate_global_root(
        class_commitment: &Felt,
        storage_commitment: Felt,
    ) -> Result<Felt, jsonrpc::Error> {
        let global_state_ver =
            FieldElement::from_byte_slice_be(b"STARKNET_STATE_V0").map_err(|_| {
                jsonrpc::Error::new(-32701, "Failed to create Field Element".to_string())
            })?;
        let hash = poseidon_hash_many(&[
            global_state_ver,
            FieldElement::from_hex_be(storage_commitment.as_ref()).map_err(|_| {
                jsonrpc::Error::new(-32701, "Failed to create Field Element".to_string())
            })?,
            FieldElement::from_hex_be(class_commitment.as_ref()).map_err(|_| {
                jsonrpc::Error::new(-32701, "Failed to create Field Element".to_string())
            })?,
        ]);
        Felt::try_new(&format!("0x{:x}", hash))
            .map_err(|_| jsonrpc::Error::new(-32701, "Failed to create Field Element".to_string()))
    }

    fn parse_proof(
        key: impl Into<String>,
        value: Felt,
        proof: &[Node],
    ) -> Result<Option<Felt>, jsonrpc::Error> {
        let key = felt_to_bits(FieldElement::from_hex_be(&key.into()).map_err(|_| {
            jsonrpc::Error::new(-32701, "Failed to create Field Element".to_string())
        })?);
        if key.len() != 251 {
            return Ok(None);
        }
        let value = FieldElement::from_hex_be(value.as_ref()).map_err(|_| {
            jsonrpc::Error::new(-32701, "Failed to create Field Element".to_string())
        })?;
        // initialized to the value so if the last node
        // in the proof is a binary node we can still verify
        let (mut hold, mut path_len) = (value, 0);
        // reverse the proof in order to hash from the leaf towards the root
        for (i, node) in proof.iter().rev().enumerate() {
            match node {
                Node::EdgeNode(EdgeNode {
                    edge: EdgeNodeEdge { child, path },
                }) => {
                    // calculate edge hash given by provider
                    let child_felt = FieldElement::from_hex_be(child.as_ref()).map_err(|_| {
                        jsonrpc::Error::new(-32701, "Failed to create Field Element".to_string())
                    })?;
                    let path_value =
                        FieldElement::from_hex_be(path.value.as_ref()).map_err(|_| {
                            jsonrpc::Error::new(
                                -32701,
                                "Failed to create Field Element".to_string(),
                            )
                        })?;
                    let provided_hash = pedersen_hash(&child_felt, &path_value)
                        + FieldElement::from(path.len as u64);
                    if i == 0 {
                        // mask storage key
                        let computed_hash =
                            match felt_from_bits(&key, Some(251 - path.len as usize)) {
                                Ok(masked_key) => {
                                    pedersen_hash(&value, &masked_key)
                                        + FieldElement::from(path.len as u64)
                                }
                                Err(_) => return Ok(None),
                            };
                        // verify computed hash against provided hash
                        if provided_hash != computed_hash {
                            return Ok(None);
                        };
                    }

                    // walk up the remaining path
                    path_len += path.len;
                    hold = provided_hash;
                }
                Node::BinaryNode(BinaryNode {
                    binary: BinaryNodeBinary { left, right },
                }) => {
                    path_len += 1;
                    let left = FieldElement::from_hex_be(left.as_ref()).map_err(|_| {
                        jsonrpc::Error::new(-32701, "Failed to create Field Element".to_string())
                    })?;
                    let right = FieldElement::from_hex_be(right.as_ref()).map_err(|_| {
                        jsonrpc::Error::new(-32701, "Failed to create Field Element".to_string())
                    })?;
                    // identify path direction for this node
                    let expected_hash = match Direction::from(key[251 - path_len as usize]) {
                        Direction::Left => pedersen_hash(&hold, &right),
                        Direction::Right => pedersen_hash(&left, &hold),
                    };

                    hold = pedersen_hash(&left, &right);
                    // verify calculated hash vs provided hash for the node
                    if hold != expected_hash {
                        return Ok(None);
                    };
                }
            };
        }

        Ok(Some(Felt::try_new(&format!("0x{:x}", hold))?))
    }
}
