# @caesar/crypto

Shared cryptography package for Caesar App, providing type-safe wrappers around the Web Crypto API.

## Features

- **Key Derivation**: Scrypt-based password key derivation
- **Symmetric Encryption**: AES-GCM for data encryption
- **Asymmetric Encryption**: RSA-OAEP for public key encryption
- **Key Exchange**: ECDH for shared secret derivation
- **Type Safety**: Full TypeScript support with strict types

## Installation

This is an internal workspace package. Add to your package dependencies:

```json
{
  "dependencies": {
    "@caesar/crypto": "workspace:*"
  }
}
```

## Usage

```typescript
import type {
  ScryptParams,
  EncryptedData,
  RsaKeyPair,
  SymmetricKey,
} from "@caesar/crypto";
```

## Implementation Status

- [x] Type definitions (Issue #84)
- [ ] Key derivation functions (Issue #85)
- [ ] Symmetric encryption (Issue #86)
- [ ] Asymmetric encryption & ECDH (Issue #87)

## Architecture

This package follows the Web Crypto API standards:

- **Scrypt**: Key derivation from passwords
- **AES-GCM**: Authenticated encryption with 128/192/256-bit keys
- **RSA-OAEP**: Public key encryption with 2048/3072/4096-bit keys
- **ECDH**: Key agreement using P-256/P-384/P-521 curves

## Development

```bash
# Build the package
bun run build

# Watch mode
bun run dev

# Format check
bun run check
bun run check:fix

# Clean build artifacts
bun run clean
```

## License

Private - Caesar Team
