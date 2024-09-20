# ECPM (Elliptic Curve Protocol for Messaging)

ECPM is a secure messaging protocol that utilizes Elliptic Curve Cryptography (ECC) for key exchange and AES for message encryption.

This implementation establishes secure communication while ensuring message integrity and authenticity through digital signatures and MAC (Message Authentication Code).

## Features

- **ECC** for secure key exchange.
- **AES-GCM** for message encryption.
- **HMAC with SHA3-512** for message integrity.
- Key derivation using PBKDF2.
- Support for mnemonic phrases.

## Requirements

- Python 3.9 or newer
- Required packages: `cryptography`

Install the required packages using:
```bash
pip install cryptography
```

## Usage

See `application.py` for a complete example of how to use ECPM. The key steps include:

- **Key Generation:** Create ECC key pairs for Alice and Bob.
- **Key Exchange:** Establish a shared key using ECDH.
- **Message Encryption/Decryption:** Use AES for encrypting and decrypting messages.
- **Digital Signatures:** Sign and verify messages to ensure authenticity.

## Acknowledgments

- The `cryptography` library for its cryptographic primitives.
- The concept of ECIES for inspiration.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.
