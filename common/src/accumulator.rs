//! This module provides a generic framework, and a Merkle-tree based implementation,
//! for vector accumulators. This allows a party (the verifier) to outsource the storage
//! of the vector to another party (the prover). The verifier only maintains a single
//! hash that commits to the entire vector, and retrieves the elements of the vector,
//! or updates their content, by sending requests to the prover.
//! Each retrieval or update operation is guaranteed by an accompanied proof, that is
//! produced by the prover.

use alloc::{vec, vec::Vec};
use core::{error::Error, fmt, marker::PhantomData, mem::MaybeUninit};
use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug)]
pub enum AccumulatorError {
    IndexOutOfBounds,
}

impl fmt::Display for AccumulatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AccumulatorError::IndexOutOfBounds => write!(f, "Index out of bounds"),
        }
    }
}

impl Error for AccumulatorError {}

/// A trait representing a cryptographic hasher that produces a fixed-size output.
pub trait Hasher<const OUTPUT_SIZE: usize>: Sized {
    /// Creates a new instance of the hasher.
    fn new() -> Self;

    /// Updates the hasher with the given data.
    ///
    /// # Arguments
    ///
    /// * `data` - A slice of bytes to be hashed.
    fn update(&mut self, data: &[u8]) -> &mut Self;

    /// Finalizes the hashing process and writes the output to an array of bytes.
    fn digest(self, out: &mut [u8; OUTPUT_SIZE]);

    /// Finalizes the hashing process and returns the output as an array of bytes.
    fn finalize(self) -> [u8; OUTPUT_SIZE] {
        let mut out = MaybeUninit::<[u8; OUTPUT_SIZE]>::uninit();
        // SAFETY: the call to `digest` will fully initialize the output array.
        let out_ref = unsafe { &mut *out.as_mut_ptr() };
        self.digest(out_ref);
        unsafe { out.assume_init() }
    }

    /// Convenience method to hash data in a single step.
    ///
    /// # Arguments
    ///
    /// * `data` - A slice of bytes to be hashed.
    ///
    /// # Returns
    ///
    /// A fixed-size output array of bytes representing the hash.
    fn hash(data: &[u8]) -> [u8; OUTPUT_SIZE] {
        let mut hasher = Self::new();
        hasher.update(data);
        let mut out = [0u8; OUTPUT_SIZE];
        hasher.digest(&mut out);
        out
    }
}

/// A wrapper type for fixed-size byte arrays used to represent hash outputs.
///
/// This wrapper allows implementing serialization and deserialization traits
/// for byte arrays of arbitrary lengths, which is not natively supported by Serde.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HashOutput<const N: usize>(pub [u8; N]);

impl<const N: usize> Serialize for HashOutput<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<const N: usize> From<[u8; N]> for HashOutput<N> {
    fn from(array: [u8; N]) -> Self {
        HashOutput(array)
    }
}

impl<const N: usize> From<HashOutput<N>> for [u8; N] {
    fn from(hash: HashOutput<N>) -> Self {
        hash.0
    }
}

impl<'de, const N: usize> Deserialize<'de> for HashOutput<N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let slice: &[u8] = Deserialize::deserialize(deserializer)?;
        let array: [u8; N] = slice
            .try_into()
            .map_err(|_| serde::de::Error::custom("Incorrect length"))?;
        Ok(HashOutput(array))
    }
}

/// A trait representing a cryptographic vector accumulator, that can generate and verify
/// proofs of inclusion and updates.
pub trait VectorAccumulator<
    T: AsRef<[u8]> + Clone + Serialize + DeserializeOwned,
    H: Clone + Serialize + DeserializeOwned,
>
{
    /// The type representing an inclusion proof.
    type InclusionProof: Serialize + DeserializeOwned;

    /// The type representing a reference to an inclusion proof.
    type InclusionProofRef<'a>;

    /// The type representing an update proof.
    type UpdateProof: Serialize + DeserializeOwned;

    /// The type representing a reference to an update proof.
    type UpdateProofRef<'a>;

    /// Creates a new accumulator with the given data.
    fn new(data: Vec<T>) -> Self;

    /// Returns the a reference to the i-th element in the vector, or None if the index is out of bounds.
    fn get(&self, index: usize) -> Option<&T>;

    /// Returns the size of the vector.
    fn size(&self) -> usize;

    /// Returns the root hash of the accumulator.
    fn root(&self) -> &H;

    /// Generates a proof of inclusion for an element at the given index.
    /// Returns the inclusion proof, or an error string if the index is out of bounds.
    fn prove(&self, index: usize) -> Result<Self::InclusionProof, AccumulatorError>;

    /// Computes the hash of an element.
    fn hash_element<T_: AsRef<[u8]>>(element: &T_) -> H;

    /// Verifies an inclusion proof. This associated function is called by the verifier,
    /// rather than the owner of the instance.
    ///
    /// # Arguments
    ///
    /// * `root` - The expected root hash of the accumulator.
    /// * `proof` - The inclusion proof to verify.
    /// * `value_hash` - The hash of the element.
    /// * `index` - The index of the element.
    /// * `size` - The size of the accumulator.
    ///
    /// # Returns
    ///
    /// `true` if the proof is valid, `false` otherwise.
    fn verify_inclusion_proof<'a>(
        root: &H,
        proof: Self::InclusionProofRef<'a>,
        value_hash: &H,
        index: usize,
        size: usize,
    ) -> bool;

    /// Updates the accumulator by replacing the element at the given index.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the element to be updated.
    /// * `value` - The new value to replace the existing element.
    ///
    /// # Returns
    ///
    /// An update proof, or an error string if the index is out of bounds.
    fn update(&mut self, index: usize, value: T) -> Result<Self::UpdateProof, AccumulatorError>;

    /// Verifies an update proof. This associated function is called by the verifier,
    /// rather than the owner of the instance.
    ///
    /// # Arguments
    ///
    /// * `old_root` - The expected old root hash before the update.
    /// * `update_proof` - The update proof to verify.
    /// * `old_value_hash` - The hash of the old value of the element before the update.
    /// * `new_value_hash` - The hash of the new value of the element after the update.
    /// * `index` - The index of the element.
    /// * `size` - The size of the accumulator.
    ///
    /// # Returns
    ///
    /// `true` if the update proof is valid, `false` otherwise.
    fn verify_update_proof<'a>(
        old_root: &H,
        update_proof: Self::UpdateProofRef<'a>,
        old_value_hash: &H,
        new_value_hash: &H,
        index: usize,
        size: usize,
    ) -> bool;
}

/// A Merkle tree-based implementation of the `VectorAccumulator` trait.
pub struct MerkleAccumulator<
    H: Hasher<OUTPUT_SIZE>,
    T: AsRef<[u8]> + Clone + Serialize + DeserializeOwned,
    const OUTPUT_SIZE: usize,
> {
    data: Vec<T>,
    tree: Vec<HashOutput<OUTPUT_SIZE>>,
    _marker: PhantomData<H>,
}

impl<
        H: Hasher<OUTPUT_SIZE>,
        T: AsRef<[u8]> + Clone + Serialize + DeserializeOwned,
        const OUTPUT_SIZE: usize,
    > VectorAccumulator<T, HashOutput<OUTPUT_SIZE>> for MerkleAccumulator<H, T, OUTPUT_SIZE>
{
    type InclusionProof = Vec<HashOutput<OUTPUT_SIZE>>;
    type InclusionProofRef<'a> = &'a [HashOutput<OUTPUT_SIZE>];

    // the update proof is a Merkle proof, plus the new root of the tree
    type UpdateProof = (Self::InclusionProof, HashOutput<OUTPUT_SIZE>);
    type UpdateProofRef<'a> = (&'a [HashOutput<OUTPUT_SIZE>], &'a HashOutput<OUTPUT_SIZE>);

    /// Creates a new `MerkleAccumulator` with the given data.
    ///
    /// # Arguments
    ///
    /// * `data` - A vector of elements to be included in the Merkle tree.
    fn new(data: Vec<T>) -> Self {
        let mut ma = MerkleAccumulator {
            data,
            tree: Vec::new(),
            _marker: PhantomData,
        };
        ma.build_tree();
        ma
    }

    fn get(&self, index: usize) -> Option<&T> {
        self.data.get(index)
    }

    fn size(&self) -> usize {
        self.data.len()
    }

    /// Returns the root hash of the Merkle tree.
    fn root(&self) -> &HashOutput<OUTPUT_SIZE> {
        &self.tree[0]
    }

    /// Generates a proof of inclusion for an element at the given index.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the element for which to generate a proof.
    ///
    /// # Returns
    ///
    /// An inclusion proof as a vector of hash outputs.
    fn prove(&self, index: usize) -> Result<Self::InclusionProof, AccumulatorError> {
        if index >= self.data.len() {
            return Err(AccumulatorError::IndexOutOfBounds);
        }

        let mut proof = Vec::new();
        let n = self.data.len();
        let mut pos = n - 1 + index;

        while pos > 0 {
            if pos % 2 == 0 {
                proof.push(self.tree[pos - 1].clone());
            } else {
                proof.push(self.tree[pos + 1].clone());
            }
            pos = (pos - 1) / 2;
        }
        Ok(proof)
    }

    /// Verifies an inclusion proof for a given element hash and index
    fn verify_inclusion_proof<'a>(
        root: &HashOutput<OUTPUT_SIZE>,
        proof: Self::InclusionProofRef<'a>,
        value_hash: &HashOutput<OUTPUT_SIZE>,
        index: usize,
        size: usize,
    ) -> bool {
        let mut hash = value_hash.clone();
        let mut pos = size - 1 + index;
        for sibling_hash in proof.iter() {
            let (left, right) = if pos % 2 == 0 {
                (sibling_hash, &hash)
            } else {
                (&hash, sibling_hash)
            };
            hash = Self::hash_internal_node(left, right);
            pos = (pos - 1) / 2;
        }
        &hash == root
    }

    /// Updates the Merkle tree by replacing the element at the given index.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the element to be updated.
    /// * `value` - The new value to replace the existing element.
    ///
    /// # Returns
    ///
    /// An update proof, or an error string if the index is out of bounds.
    fn update(&mut self, index: usize, value: T) -> Result<Self::UpdateProof, AccumulatorError> {
        if index >= self.data.len() {
            return Err(AccumulatorError::IndexOutOfBounds);
        }

        let merkle_proof = self.prove(index)?; // Capture proof before update
        self.data[index] = value;
        let n = self.data.len();
        let mut pos = n - 1 + index;
        self.tree[pos] = Self::hash_leaf(&self.data[index]);

        while pos > 0 {
            pos = (pos - 1) / 2;
            self.tree[pos] =
                Self::hash_internal_node(&self.tree[2 * pos + 1], &self.tree[2 * pos + 2]);
        }

        let new_root = self.root();
        Ok((merkle_proof, new_root.clone()))
    }

    /// Verifies an update proof.
    fn verify_update_proof<'a>(
        old_root: &HashOutput<OUTPUT_SIZE>,
        update_proof: Self::UpdateProofRef<'a>,
        old_value_hash: &HashOutput<OUTPUT_SIZE>,
        new_value_hash: &HashOutput<OUTPUT_SIZE>,
        index: usize,
        size: usize,
    ) -> bool {
        let (proof, new_root) = update_proof;

        // verify that the old value was correct with old root, and the new value is correct with new root
        Self::verify_inclusion_proof(old_root, proof, old_value_hash, index, size)
            && Self::verify_inclusion_proof(new_root, proof, new_value_hash, index, size)
    }

    /// Computes the hash of an element.
    #[inline]
    fn hash_element<T_: AsRef<[u8]>>(element: &T_) -> HashOutput<OUTPUT_SIZE> {
        Self::hash_leaf(element)
    }
}

impl<
        H: Hasher<OUTPUT_SIZE>,
        T: AsRef<[u8]> + Clone + Serialize + DeserializeOwned,
        const OUTPUT_SIZE: usize,
    > MerkleAccumulator<H, T, OUTPUT_SIZE>
{
    /// Constructs the Merkle tree from the provided data.
    fn build_tree(&mut self) {
        let n = self.data.len();
        let leaves = self
            .data
            .iter()
            .map(|x| Self::hash_leaf(x))
            .collect::<Vec<_>>();

        self.tree = vec![HashOutput([0u8; OUTPUT_SIZE]); 2 * n - 1];
        self.tree[n - 1..].clone_from_slice(&leaves);

        for i in (0..n - 1).rev() {
            self.tree[i] = Self::hash_internal_node(&self.tree[2 * i + 1], &self.tree[2 * i + 2]);
        }
    }

    /// Computes the hash for a leaf node. A 0x00 byte is prepended to the data before hashing the element.
    fn hash_leaf<T_: AsRef<[u8]>>(data: &T_) -> HashOutput<OUTPUT_SIZE> {
        let mut hasher = H::new();
        hasher.update(&[0x00]);
        hasher.update(data.as_ref());
        let mut digest = [0u8; OUTPUT_SIZE];
        hasher.digest(&mut digest);
        HashOutput(digest)
    }

    /// Computes the hash for an internal node. A 0x01 byte is prepended to the data before hashing the child nodes.
    fn hash_internal_node(
        left: &HashOutput<OUTPUT_SIZE>,
        right: &HashOutput<OUTPUT_SIZE>,
    ) -> HashOutput<OUTPUT_SIZE> {
        // prepend a 0x01 byte to the data before hashing internal nodes
        let mut hasher = H::new();
        hasher.update(&[0x01]);
        hasher.update(&left.0);
        hasher.update(&right.0);
        let mut digest = [0u8; OUTPUT_SIZE];
        hasher.digest(&mut digest);
        HashOutput(digest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use sha2::{Digest, Sha256};

    // Example implementation of the Hasher trait using SHA-256
    pub struct Sha256Hasher {
        hasher: Sha256,
    }

    impl Hasher<32> for Sha256Hasher {
        fn new() -> Self {
            Sha256Hasher {
                hasher: Sha256::new(),
            }
        }

        fn update(&mut self, data: &[u8]) -> &mut Self {
            self.hasher.update(data);
            self
        }

        fn digest(self, out: &mut [u8; 32]) {
            let result = self.hasher.finalize();
            out.copy_from_slice(&result);
        }
    }

    // utility function to generate test vectors of different length
    fn generate_test_data(size: usize) -> Vec<Vec<u8>> {
        (1..=size)
            .map(|i| format!("data{}", i).into_bytes())
            .collect()
    }

    #[test]
    fn test_out_of_bounds_proof_generation() {
        let data = generate_test_data(3);
        let ma = MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::new(data.clone());

        // Trying to prove an element at an out-of-bounds index should return an error
        assert!(ma.prove(3).is_err());
    }

    #[test]
    fn test_out_of_bounds_update() {
        let data = generate_test_data(3);
        let mut ma = MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::new(data.clone());

        // Trying to update an element at an out-of-bounds index should return an error
        assert!(ma.update(3, b"new_data".to_vec()).is_err());
    }

    #[test]
    fn test_verify_incorrect_proof() {
        let data = generate_test_data(4);

        let ma = MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::new(data.clone());
        let root = ma.root();

        // Generate a proof for one element and try to verify it with another
        let proof = ma.prove(0).unwrap();
        let elem_hash = MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::hash_leaf(&data[1]);
        assert!(
            !MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::verify_inclusion_proof(
                &root,
                &proof,
                &elem_hash,
                1,
                data.len()
            )
        );
    }

    #[test]
    fn test_update_proof_with_incorrect_values() {
        let data = generate_test_data(4);

        let mut ma = MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::new(data.clone());
        let old_root = ma.root().clone();

        // Update an element
        let new_data = b"new_data".to_vec();
        let update_proof = ma.update(2, new_data.clone()).unwrap();
        let new_root = ma.root().clone();

        let old_elem_hash = MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::hash_leaf(&data[2]);
        let new_elem_hash = MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::hash_leaf(&new_data);
        let incorrect_elem_hash =
            MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::hash_leaf(&data[0]);

        // Verify update proof is false with incorrect old root
        assert!(
            !MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::verify_update_proof(
                &new_root, // Incorrect, we pass new_root instead of the old_root
                (&update_proof.0, &update_proof.1),
                &old_elem_hash,
                &new_elem_hash,
                2,
                data.len()
            )
        );

        // Verify update proof is false with incorrect old value hash
        assert!(
            !MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::verify_update_proof(
                &old_root,
                (&update_proof.0, &update_proof.1),
                &incorrect_elem_hash, // Incorrect old value hash
                &new_elem_hash,
                2,
                data.len()
            )
        );

        // Verify update proof is false with incorrect new value hash
        assert!(
            !MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::verify_update_proof(
                &new_root,
                (&update_proof.0, &update_proof.1),
                &old_elem_hash,
                &incorrect_elem_hash, // Incorrect new value hash
                2,
                data.len()
            )
        );
    }

    #[test]
    fn test_merkle_accumulator() {
        let data = vec![
            b"data1".to_vec(),
            b"data2".to_vec(),
            b"data3".to_vec(),
            b"data4".to_vec(),
        ];

        let mut ma = MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::new(data.clone());

        let root = ma.root().clone();

        let proof = ma.prove(2).unwrap();
        let elem_hash = MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::hash_leaf(&data[2]);
        assert!(
            MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::verify_inclusion_proof(
                &root,
                &proof,
                &elem_hash,
                2,
                data.len()
            )
        );

        // Update an element and check if root changes
        let new_data = b"new_data".to_vec();
        let update_proof = ma.update(2, new_data.clone()).unwrap();
        let new_root = ma.root();
        assert_ne!(&root, new_root);

        let new_proof = ma.prove(2).unwrap();
        let new_elem_hash = MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::hash_leaf(&new_data);
        assert!(
            MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::verify_inclusion_proof(
                &new_root,
                &new_proof,
                &new_elem_hash,
                2,
                data.len()
            )
        );

        // Verify the update proof
        let old_elem_hash = MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::hash_leaf(&data[2]);
        assert!(
            MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::verify_update_proof(
                &root, // old root
                (&update_proof.0, &update_proof.1),
                &old_elem_hash,
                &new_elem_hash,
                2,
                data.len()
            )
        );

        // Test that serializing/deserializing inclusion proofs and update proofs works
        let serialized_proof: Vec<u8> = postcard::to_allocvec(&proof).unwrap();
        let deserialized_proof: Vec<HashOutput<32>> =
            postcard::from_bytes(&serialized_proof).unwrap();
        assert_eq!(proof, deserialized_proof);

        let serialized_update_proof = postcard::to_allocvec(&update_proof).unwrap();
        let deserialized_update_proof: (Vec<HashOutput<32>>, HashOutput<32>) =
            postcard::from_bytes(&serialized_update_proof).unwrap();
        assert_eq!(update_proof, deserialized_update_proof);
    }
}
