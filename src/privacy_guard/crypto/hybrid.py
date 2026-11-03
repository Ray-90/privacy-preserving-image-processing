# AES-256-GCM payload encryption with RSA-OAEP-SHA256 key wrapping.
import os
import struct
from pathlib import Path
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from privacy_guard.crypto.format import MAGIC, MAX_PLAINTEXT, MAX_PACKAGE
from privacy_guard.crypto.keys import load_public, load_private, oaep
from privacy_guard.file_io import read_bounded, write_new


def encrypt_file(source, destination, public_key_path):
    """Encrypt exact file bytes, then remove the unchanged original file."""
    source = Path(source)
    if source.is_symlink() or source.stat().st_nlink != 1:
        raise ValueError('Choose a regular source file, not a link or hard link.')
    plaintext = read_bounded(source, MAX_PLAINTEXT)
    encrypted = encrypt_bytes(plaintext, public_key_path)
    write_new(destination, encrypted)
    if (read_bounded(destination, MAX_PACKAGE) != encrypted
            or read_bounded(source, MAX_PLAINTEXT) != plaintext):
        raise ValueError('Source or saved ciphertext changed; original was kept.')
    try:
        source.unlink()
    except OSError as exc:
        raise OSError(f'Encrypted file saved, but original could not be removed: {source}') from exc


def encrypt_bytes(plaintext, public_key_path):
    if len(plaintext) > MAX_PLAINTEXT:
        raise ValueError('Plaintext exceeds supported size limit.')
    public_key = load_public(public_key_path)
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    wrapped_key = public_key.encrypt(aes_key, oaep())
    header = MAGIC + struct.pack('>H', len(wrapped_key)) + wrapped_key + nonce
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, header)
    return header + ciphertext


def decrypt_file(source, destination, private_key_path, password):
    """Authenticate in memory before opening the plaintext destination."""
    package = read_bounded(source, MAX_PACKAGE)
    write_new(destination, decrypt_bytes(package, private_key_path, password))


def decrypt_bytes(package, private_key_path, password):
    if len(package) > MAX_PACKAGE:
        raise ValueError('Encrypted payload exceeds supported size limit.')
    if len(package) < 10 or package[:8] != MAGIC:
        raise ValueError('Invalid or unsupported encrypted-file format.')
    wrapped_size = struct.unpack('>H', package[8:10])[0]
    header_size = 10 + wrapped_size + 12
    if not 256 <= wrapped_size <= 1024 or len(package) < header_size + 16:
        raise ValueError('Invalid or truncated encrypted file.')
    if len(package) - header_size - 16 > MAX_PLAINTEXT:
        raise ValueError('Encrypted payload exceeds supported size limit.')
    private_key = load_private(private_key_path, password)
    if wrapped_size != (private_key.key_size + 7) // 8:
        raise ValueError('Decryption failed: incorrect key or damaged file.')
    wrapped_key = package[10:10 + wrapped_size]
    nonce = package[10 + wrapped_size:header_size]
    try:
        aes_key = private_key.decrypt(wrapped_key, oaep())
        if len(aes_key) != 32:
            raise ValueError('Invalid AES key size')
        plaintext = AESGCM(aes_key).decrypt(nonce, package[header_size:], package[:header_size])
    except (ValueError, InvalidTag) as exc:
        raise ValueError('Decryption failed: incorrect key or damaged file.') from exc
    return plaintext
