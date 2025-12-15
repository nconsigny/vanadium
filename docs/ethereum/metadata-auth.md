# Metadata Authentication Model

## Overview

The V-App displays transaction details using metadata (token names, decimals, domain names, contract methods). Since metadata comes from the untrusted host, it MUST be cryptographically authenticated before display as trusted information.

## Trust Model

### Trusted Authority
Ledger's Crypto Asset List (CAL) provides signed metadata. The V-App contains the CAL public key for verification.

### Trust Chain
```
Ledger CAL Key (embedded in V-App)
        |
        v
   CAL Signature
        |
        v
   Metadata (token info, etc.)
        |
        v
   Verified & cached in V-App
        |
        v
   Displayed to user as trusted
```

## Metadata Types

### ERC-20 Token Info
```
{
  chain_id: u64,
  contract_address: [u8;20],
  ticker: String,      // e.g., "USDC"
  decimals: u8,        // e.g., 6
}
```
**Signed by:** CAL key
**Used for:** Displaying token amounts in human-readable form

### NFT Collection Info
```
{
  chain_id: u64,
  contract_address: [u8;20],
  collection_name: String,
}
```
**Signed by:** CAL key
**Used for:** Displaying NFT transfers with collection name

### Domain Name Resolution
```
{
  address: [u8;20],
  domain: String,      // e.g., "vitalik.eth"
  resolver: String,    // e.g., "ENS"
}
```
**Signed by:** Domain resolution authority
**Used for:** Displaying recipient as domain name

### Contract Method Info
```
{
  chain_id: u64,
  contract_address: [u8;20],
  selector: [u8;4],
  method_name: String,
  parameters: Vec<ParamInfo>,
}
```
**Signed by:** CAL key
**Used for:** Decoding and displaying contract calls

## Signature Verification

### Signature Format
```
signature = ECDSA_sign(CAL_private_key, keccak256(metadata_blob))
```

### Verification Steps
1. Deserialize metadata from host
2. Reconstruct canonical metadata blob
3. Compute `keccak256(metadata_blob)`
4. Verify ECDSA signature against CAL public key
5. If valid, cache metadata for session
6. If invalid, reject with `INVALID_SIGNATURE`

### Key Storage
CAL public key is compiled into V-App binary. Key rotation requires V-App update.

## Caching Rules

### Session Cache
- Verified metadata cached in V-App memory
- Cache key: `(chain_id, contract_address)` or `(address)` for domains
- Cache cleared on app exit

### Cache Lookup
```
1. Receive transaction
2. Extract contract address and chain ID
3. Look up in session cache
4. If found: use for display
5. If not found: display raw address/hex OR require blind-signing
```

### Cache Limits
- Maximum entries per type: 100
- LRU eviction when full
- No persistence across sessions

## Display Without Metadata

When metadata is unavailable or unverified:

### Option 1: Raw Display
Show raw hex addresses and values. User sees exact on-chain data.

### Option 2: Blind Signing Warning
```
[ Warning: Unknown Contract ]
Address: 0xdAC1...
Selector: 0xa9059cbb

[ Enable blind signing to continue ]
```

### Option 3: Reject
For high-risk operations, refuse without verified metadata.

## Metadata Freshness

- Version binding: Metadata signed with CAL version; reject outdated
- Expiration: Optional timestamp checked against RTC
- Revocation: CAL publishes revocation lists

## Security Considerations

- **Signature malleability**: Use canonical format, reject non-canonical
- **Replay across chains**: chain_id included; cannot cross-chain replay
- **Collision attacks**: Structured encoding with length prefixes
- **Display truncation**: Show "..." but verify full hash
