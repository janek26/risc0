pub mod utils {
    use zexe_algebra::Fp;

    pub fn to_field_element(x: u64) -> Result<Fp> {
        let bytes = x.to_be_bytes();
        Fp::from_bytes(&bytes).ok()
    }

    pub fn to_u64(x: Fp) -> u64 {
        let bytes = x.to_bytes();
        u64::from_be_bytes(bytes.try_into().unwrap())
    }
}
