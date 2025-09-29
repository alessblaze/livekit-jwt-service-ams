# Matrix Identity Verification

## Environment Variables

```bash
# Base64-encoded Ed25519 private key (64 bytes)
MATRIX_PRIVATE_KEY="base64-encoded-private-key"

# Base64-encoded Synapse public key (32 bytes) 
SYNAPSE_PUBLIC_KEY="base64-encoded-synapse-public-key"
```

## Key Generation

```go
// Generate new key pair
publicKey, privateKey, _ := ed25519.GenerateKey(nil)

// Encode for environment variables
privateKeyB64 := base64.StdEncoding.EncodeToString(privateKey)
publicKeyB64 := base64.StdEncoding.EncodeToString(publicKey)
```

## Error Codes

- `M_INVALID_SIGNATURE` - Ed25519 signature verification failed
- `M_CLOCK_SKEW` - Timestamp outside ±30s window  
- `M_MISSING_PARAM` - Required fields missing

## Flow

1. Generate UUID session ID, timestamp, nonce
2. Sign payload with Ed25519 private key
3. POST to `/_matrix/client/r0/identity/verify`
4. Verify response signature with Synapse public key
5. Validate session ID, nonce, timestamp match