// TODO: can we get rid of this module and use the corresponding code from vlib-bitcoin?

use bitcoin::{consensus::encode, VarInt};
use sdk::hash::{Hasher, Sha256};

use crate::{
    accounts::{DescriptorTemplate, KeyInformation, TapTree},
    script::{ScriptContext, ToScriptWithKeyInfo},
};

pub const BIP0341_TAPBRANCH_TAG: &[u8; 9] = b"TapBranch";
pub const BIP0341_TAPLEAF_TAG: &[u8; 7] = b"TapLeaf";

fn new_tagged_hash(tag: &[u8]) -> Sha256 {
    let mut hashtag = [0u8; 32];
    {
        let mut sha256hasher = Sha256::new();
        sha256hasher.update(tag);
        sha256hasher.digest(&mut hashtag);
    }

    let mut hash_context = Sha256::new();
    hash_context.update(&hashtag);
    hash_context.update(&hashtag);

    hash_context
}

fn tagged_hash(tag: &[u8], data: &[u8], data2: Option<&[u8]>) -> [u8; 32] {
    let mut hash_context = new_tagged_hash(tag);
    let mut out: [u8; 32] = [0; 32];

    hash_context.update(data);

    if let Some(data2) = data2 {
        hash_context.update(data2);
    }

    hash_context.digest(&mut out);

    out
}

pub trait GetTapTreeHash {
    fn get_taptree_hash(
        &self,
        key_information: &[KeyInformation],
        is_change: bool,
        address_index: u32,
    ) -> Result<[u8; 32], &'static str>;
}

impl GetTapTreeHash for TapTree {
    fn get_taptree_hash(
        &self,
        key_information: &[KeyInformation],
        is_change: bool,
        address_index: u32,
    ) -> Result<[u8; 32], &'static str> {
        match self {
            TapTree::Script(leaf_desc) => {
                leaf_desc.get_tapleaf_hash(key_information, is_change, address_index)
            }
            TapTree::Branch(l, r) => {
                let hash_left = l.get_taptree_hash(key_information, is_change, address_index)?;
                let hash_right = r.get_taptree_hash(key_information, is_change, address_index)?;
                if hash_left <= hash_right {
                    Ok(tagged_hash(
                        BIP0341_TAPBRANCH_TAG,
                        &hash_left,
                        Some(&hash_right),
                    ))
                } else {
                    Ok(tagged_hash(
                        BIP0341_TAPBRANCH_TAG,
                        &hash_right,
                        Some(&hash_left),
                    ))
                }
            }
        }
    }
}

pub trait GetTapLeafHash {
    fn get_tapleaf_hash(
        &self,
        key_information: &[KeyInformation],
        is_change: bool,
        address_index: u32,
    ) -> Result<[u8; 32], &'static str>;
}

impl GetTapLeafHash for DescriptorTemplate {
    fn get_tapleaf_hash(
        &self,
        key_information: &[KeyInformation],
        is_change: bool,
        address_index: u32,
    ) -> Result<[u8; 32], &'static str> {
        let mut ctx = new_tagged_hash(BIP0341_TAPLEAF_TAG);
        ctx.update(&[0xC0u8]); // leaf version
        let leaf_script =
            self.to_script(key_information, is_change, address_index, ScriptContext::Tr)?;
        ctx.update(&encode::serialize(&VarInt(leaf_script.len() as u64)));
        ctx.update(&leaf_script.to_bytes());

        let mut result = [0u8; 32];
        ctx.digest(&mut result);
        Ok(result)
    }
}
