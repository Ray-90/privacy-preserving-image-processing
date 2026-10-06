"""Hybrid whole-file encryption: AES-256-GCM + RSA-OAEP-SHA256.

Usage and format are documented in ENCRYPTION.md. No YOLO dependency required.
"""
import argparse
import getpass
import os
from pathlib import Path
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b'ISLENC01'
MAX_PLAINTEXT = 64 * 1024 * 1024
MAX_PACKAGE = MAX_PLAINTEXT + 4096


def oaep():
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                        algorithm=hashes.SHA256(), label=None)


def read_bounded(path, limit):
    with Path(path).open('rb') as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f'File exceeds supported size limit: {path}')
    return data


def write_new(path, data):
    """Never overwrite; restrict permissions on systems that support POSIX modes."""
    path = Path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def generate_keys(directory, password):
    if not password:
        raise ValueError('A nonempty private-key password is required.')
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    private_bytes = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password))
    public_bytes = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    write_new(directory / 'private.pem', private_bytes)
    write_new(directory / 'public.pem', public_bytes)
    return directory


def load_public(path):
    key = serialization.load_pem_public_key(read_bounded(path, 65536))
    if not isinstance(key, rsa.RSAPublicKey) or not 2048 <= key.key_size <= 8192:
        raise ValueError('Expected an RSA public key between 2048 and 8192 bits.')
    return key


def load_private(path, password):
    if not password:
        raise ValueError('A nonempty private-key password is required.')
    key = serialization.load_pem_private_key(read_bounded(path, 65536), password=password)
    if not isinstance(key, rsa.RSAPrivateKey) or not 2048 <= key.key_size <= 8192:
        raise ValueError('Expected an RSA private key between 2048 and 8192 bits.')
    return key


def encrypt_file(source, destination, public_key_path):
    """Encrypt exact file bytes, including any embedded image metadata."""
    plaintext = read_bounded(source, MAX_PLAINTEXT)
    write_new(destination, encrypt_bytes(plaintext, public_key_path))


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


def prompt_password(confirm=False):
    value = getpass.getpass('Private-key password: ')
    if not value:
        raise ValueError('A nonempty password is required.')
    if confirm and value != getpass.getpass('Repeat password: '):
        raise ValueError('Passwords do not match.')
    return value.encode('utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    keygen = commands.add_parser('keygen', help='Generate a new password-protected RSA key pair')
    keygen.add_argument('--directory', default='keys', help='New directory; must not already exist')
    for name in ['encrypt', 'decrypt']:
        command = commands.add_parser(name)
        command.add_argument('--input', required=True)
        command.add_argument('--output', required=True, help='New file; parent folder must exist')
        command.add_argument('--public-key' if name == 'encrypt' else '--private-key', required=True)
    args = parser.parse_args()
    try:
        if args.command == 'keygen':
            directory = generate_keys(args.directory, prompt_password(confirm=True))
            print(f'Key pair created in {directory}')
        elif args.command == 'encrypt':
            encrypt_file(args.input, args.output, args.public_key)
            print(f'Encrypted file saved: {args.output}')
        else:
            decrypt_file(args.input, args.output, args.private_key, prompt_password())
            print(f'Image restored: {args.output}')
    except (ValueError, OSError, TypeError, EOFError) as exc:
        parser.exit(1, f'Error: {exc}\n')


if __name__ == '__main__':
    main()
