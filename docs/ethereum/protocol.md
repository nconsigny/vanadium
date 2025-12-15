# Ethereum V-App Wire Protocol

## Overview

Communication between client and V-App uses a request/response protocol over the Vanadium transport layer. Messages are serialized with `postcard` (compact binary format).

## Message Structure

### Request Frame
```
+----------+------------+------------------+
| CMD (1B) | LEN (2B)   | PAYLOAD (var)    |
+----------+------------+------------------+
```

- `CMD`: Command identifier (see commands.md)
- `LEN`: Payload length (big-endian u16)
- `PAYLOAD`: Command-specific data

### Response Frame
```
+----------+------------+------------------+
| STATUS   | LEN (2B)   | PAYLOAD (var)    |
+----------+------------+------------------+
```

- `STATUS`: 0x00 = success, others = error code
- `LEN`: Payload length
- `PAYLOAD`: Response data or error details

## Command Identifiers

```
0x01  GET_APP_CONFIGURATION
0x02  GET_CHALLENGE
0x03  SIGN_TRANSACTION
0x04  SIGN_PERSONAL_MESSAGE
0x05  SIGN_EIP712_HASHED
0x06  SIGN_EIP712_MESSAGE
0x10  ETH2_GET_PUBLIC_KEY
0x11  ETH2_SET_WITHDRAWAL_INDEX
0x20  PROVIDE_ERC20_TOKEN_INFO
0x21  PROVIDE_NFT_INFO
0x22  PROVIDE_DOMAIN_NAME
0x23  LOAD_CONTRACT_METHOD_INFO
0x24  BY_CONTRACT_ADDRESS_AND_CHAIN
0x30  CLEAR_SIGN_TRANSACTION
```

## Chunking Protocol

For payloads exceeding single-message capacity:

### First Chunk
```
+------+--------+------------+-----------+
| CMD  | FLAGS  | TOTAL_LEN  | DATA      |
|      | 0x01   | (4B)       | (chunk)   |
+------+--------+------------+-----------+
```

### Continuation Chunk
```
+------+--------+------------+
| CMD  | FLAGS  | DATA       |
|      | 0x00   | (chunk)    |
+------+--------+------------+
```

### Final Chunk
```
+------+--------+------------+
| CMD  | FLAGS  | DATA       |
|      | 0x02   | (chunk)    |
+------+--------+------------+
```

FLAGS: `0x01` = FIRST, `0x00` = CONTINUE, `0x02` = LAST, `0x03` = SINGLE (first+last)

## Error Codes

```
0x00  SUCCESS
0x01  REJECTED_BY_USER
0x02  INVALID_COMMAND
0x03  INVALID_PARAMETER
0x04  INVALID_DATA
0x05  INVALID_SIGNATURE
0x06  SECURITY_VIOLATION
0x07  UNSUPPORTED_OPERATION
0x08  INTERNAL_ERROR
0x09  TIMEOUT
0x0A  BLIND_SIGNING_DISABLED
0x0B  METADATA_NOT_FOUND
0x0C  INVALID_DERIVATION_PATH
```

## Replay Protection

### Challenge-Response (Optional)
1. Client calls `GET_CHALLENGE`
2. V-App returns random 32-byte challenge
3. Client includes challenge in subsequent requests
4. V-App rejects stale/reused challenges

### Session Binding
- Metadata provision binds to current session
- Session resets on app restart
- Prevents cross-session replay of metadata

## State Machine

```
IDLE
  |-- GET_APP_CONFIGURATION --> IDLE
  |-- GET_CHALLENGE --> IDLE
  |-- PROVIDE_* --> IDLE (caches metadata)
  |-- SIGN_TRANSACTION (first chunk) --> RECEIVING_TX
  |-- SIGN_PERSONAL_MESSAGE --> AWAITING_CONFIRM
  |-- SIGN_EIP712_* --> AWAITING_CONFIRM

RECEIVING_TX
  |-- continuation chunk --> RECEIVING_TX
  |-- final chunk --> AWAITING_CONFIRM
  |-- timeout/error --> IDLE

AWAITING_CONFIRM
  |-- user confirm --> SIGNING
  |-- user reject --> IDLE (return REJECTED)
  |-- timeout --> IDLE (return TIMEOUT)

SIGNING
  |-- success --> IDLE (return signature)
  |-- error --> IDLE (return error)
```

## Timeouts

- Per-chunk: 30s | Total TX: 5min | User confirm: unlimited

## Security Considerations

- **Message ordering**: Track state; reject unexpected commands
- **Length validation**: Validate all lengths; reject oversized early
- **No implicit state**: Each command checks prerequisites explicitly
