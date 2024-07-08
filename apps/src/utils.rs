use bitvec::prelude::{BitSlice, BitVec, Msb0};
use bitvec::view::BitView;
use eyre::{eyre, Result};
use starknet::core::types::FieldElement;

pub fn felt_to_bits(felt: FieldElement) -> BitVec<u8, Msb0> {
    felt.to_bytes_be().view_bits::<Msb0>()[5..].to_bitvec()
}

pub fn felt_from_bits(bits: &BitSlice<u8, Msb0>, mask: Option<usize>) -> Result<FieldElement> {
    if bits.len() != 251 {
        return Err(eyre!("expecting 251 bits"));
    }

    let mask = match mask {
        Some(x) => {
            if x > 251 {
                return Err(eyre!("Mask cannot be bigger than 251"));
            }
            x
        }
        None => 0,
    };

    let mut bytes = [0u8; 32];
    bytes.view_bits_mut::<Msb0>()[5 + mask..].copy_from_bitslice(&bits[mask..]);

    FieldElement::from_bytes_be(&bytes).map_err(|e| eyre!(format!("{e}")))
}
