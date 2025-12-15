# Ethereum V-App UX Specification

## Overview

All security-critical information MUST be displayed on the trusted device screen before signing. The user's confirmation is the final security gate.

## Display Principles

### P1: Show What You Sign
Display MUST reflect the actual data being signed. Never display interpreted data that differs from signed payload.

### P2: Critical Fields Always Visible
Recipient, value, and fee MUST always be shown. User cannot proceed without seeing these.

### P3: Fail to Clarity
If data cannot be clearly displayed, show warning and require explicit blind-sign opt-in.

### P4: No Hidden Actions
Multi-action transactions show all actions. Batch approvals show scope.

## Device Form Factors

### Large Screen (Flex, Stax)
- Uses Page API
- Rich layouts with multiple fields
- Touch navigation

### Small Screen (Nano S+, Nano X)
- Uses Step API
- Sequential field display
- Button navigation

## Screen Flows by Operation

### ETH Transfer
```
[Screen 1: Review Transaction]
Send ETH

[Screen 2: Amount]
Amount: 1.5 ETH

[Screen 3: Recipient]
To: 0x1234...5678
    (or: vitalik.eth if domain verified)

[Screen 4: Network]
Network: Ethereum

[Screen 5: Fees]
Max Fee: 0.003 ETH

[Screen 6: Confirm]
[Hold to Sign] or [Confirm]
```

### ERC-20 Transfer
Screens: Review -> Amount (with ticker or raw) -> Recipient -> Contract -> Fees -> Confirm

### Contract Interaction (with metadata)
Screens: Review -> Method -> Parameters (N screens) -> Contract name -> Fees -> Confirm

### Contract Interaction (blind signing)
Screens: Warning -> Contract address -> Data hash -> Value -> "I understand the risk"

### Personal Message (EIP-191)
Screens: Review -> Message content (paginated) -> Signing path -> Confirm

### EIP-712 Typed Data
Screens: Review -> Domain (app, chain) -> Type -> Fields (N screens) -> Confirm

## Warning Screens

| Warning | Trigger | Action |
|---------|---------|--------|
| Blind Signing Required | Cannot decode TX | Show warning, require opt-in |
| High Value | Amount > threshold | Extra confirmation |
| Unknown Network | Unrecognized chainId | Warning + continue option |
| Non-Standard Path | Unusual BIP44 path | Warning + continue option |

## Field Formatting

| Type | Format |
|------|--------|
| Address | `0x1234...5678` (truncated) or `name.eth (0x...)` |
| ETH Amount | `1.5 ETH` (trim zeros) |
| Token Amount | `1,000.50 USDC` (with decimals) |
| Raw Amount | Full integer if no metadata |
| Hex Data | `0xabcd...1234 (N bytes)` for long data |
