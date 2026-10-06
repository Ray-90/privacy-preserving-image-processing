# Image encryption

This module encrypts a complete image file using AES-256-GCM. It generates a fresh AES key and 12-byte random nonce for every encryption. RSA-OAEP with SHA-256 protects that AES key. Decryption requires the matching RSA private key and its password. AES-GCM authenticates the encrypted contents and package header before any plaintext output is opened.

It works independently of YOLO, so you can use it while the detector is being trained. It preserves original image bytes, including metadata, without re-encoding. It supports files up to 64 MiB and processes them in memory.

## Run

Open a terminal in the extracted `credit_card_yolo` folder. To install only encryption dependencies:

```sh
python -m pip install "cryptography>=46,<51"
```

Generate your keys once:

```sh
python encryption.py keygen --directory keys
```

Enter a strong password twice when prompted. The command creates `keys/public.pem` and password-encrypted `keys/private.pem`. Keep a backup of the private key and remember its password: losing either prevents decryption. The key directory must be new. POSIX systems receive restricted file permissions; Windows access follows its own filesystem permissions.

Encrypt an image:

```sh
python encryption.py encrypt --input sample.jpg --output sample.islenc --public-key keys/public.pem
```

Restore it:

```sh
python encryption.py decrypt --input sample.islenc --output restored.jpg --private-key keys/private.pem
```

Enter the private-key password at the prompt. Use the original image extension for the restored file. Passwords are not supplied on the command line or stored by the script. The encrypted file is a binary container, not a viewable image. Output parent folders must exist; existing files are never overwritten.

## Connecting to detection

For bounding-box-only encryption, use `selective.py protect` and `selective.py restore`, documented in **SELECTIVE_ENCRYPTION.md**. That pipeline connects detection directly to region extraction, masking and encryption. This file documents the separate whole-file mode in `encryption.py`, which remains available when byte-for-byte recovery of the original file is needed.

The input image, YOLO annotated previews and detection reports remain on disk. Encrypting a file does not delete or securely erase these copies, backups or operating-system artifacts. The module implements encryption/decryption, not the proposed Windows forensic-analysis stage. It neither proves who created a package nor provides sender signatures: anyone with the public key can create a valid encrypted package.

## Container version 1

| Field | Bytes | Description |
| --- | --- | --- |
| Magic/version | 8 | ASCII ISLENC01 |
| Wrapped-key length | 2 | Unsigned big-endian integer |
| Wrapped AES key | Variable | RSA-OAEP-SHA256 ciphertext |
| Nonce | 12 | Random AES-GCM nonce |
| Ciphertext and tag | Variable | Image ciphertext followed by 16-byte GCM tag |

All bytes before the ciphertext are GCM additional authenticated data. No original filename or detector metadata is stored. File size and container structure are visible. Generated RSA keys are 3072 bits; loaded keys must be RSA, 2048–8192 bits. This educational container is project-specific and has not undergone an independent security audit.

## Tests

```sh
python -m unittest -v test_encryption.py
```

Tests cover byte-exact PNG recovery, fresh randomized encryption, modified headers/keys/nonces/ciphertext/tags, truncation, incorrect keys/passwords, refusal to overwrite files, same input/output path, read-size limits and encrypted private-key storage. These tests run independently of YOLO. Verified using cryptography 46.0.0.

Implementation references:
- https://cryptography.io/en/stable/hazmat/primitives/aead/
- https://cryptography.io/en/stable/hazmat/primitives/asymmetric/rsa/
- https://cryptography.io/en/stable/hazmat/primitives/asymmetric/serialization/
