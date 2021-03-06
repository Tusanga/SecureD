# SecureD

SecureD is a cryptography library for D that is designed to make working with cryptography simple. Simplicity encourages the developers to use cryptography in a safe and correct manner.

[![Build Status](https://travis-ci.org/LightBender/SecureD.svg?branch=master)](https://travis-ci.org/LightBender/SecureD)

## Design Philosophy

### Developer-Friendly Misuse-Resistant API
One of the largest problems with most cryptography libraries available today is that their API's practically encourage broken implementations.

### Focus on Data Storage
The primary intended use case for this library is for long-term data storage. It is not intended to be used as an SSL or streaming communications cryptography library.

### Safe by Design
Use only safe algorithms with safe modes. Make conservative choices in the implementation

### Do no re-implement Cryptography Algorithms
Use industry standard libraries instead. SecureD is based on OpenSSL.

### Minimal Code
Keep the code to a minimum. This ensures high-maintainability and eases understanding of the code.

### Unittesting
All API's are unittested using D's built in unittests. Any developer can verify the implementation with a simple 'dub test' command. This ensures that the library will perform as advertised.

## Algorithms

- HASH:				SHA2-384
- HMAC:				SHA2-384
- KDF:				PBKDF2 (HMAC/SHA2-384)
- AEAD Symmetric: 	AES-256-CTR-HMAC384
- Asymmetric:		ECC-P384 (Key Derivation + Sign/Verify with SHA2-384)
- Asymmetric:		RSA-AES-256-CTR Seal/Open, RSA only Encrypt/Decrypt and RSA only Sign/Verify
- RNG: 				System RNG on POSIX and Windows
- OTHER: 			Constant Time Equality

## Why these Algorithms?

SHA2-384 is as fast as SHA2-512 but it's truncated design serves as an effective defense against length extensions attacks.

AES-256-CTR is an alternative for GCM that offers greater security for cold-stored data when paired with a strong HMAC. GCM use a 96-bit authentication tag where the HMAC tag is a full 384 bits.
