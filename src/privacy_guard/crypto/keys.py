# RSA key generation, loading and OAEP padding.
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from privacy_guard.file_io import read_bounded, write_new


def oaep():
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                        algorithm=hashes.SHA256(), label=None)


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
    try:
        key = serialization.load_pem_private_key(read_bounded(path, 65536), password=password)
    except (ValueError, TypeError) as exc:
        raise ValueError('Incorrect private-key password or invalid private.pem file.') from exc
    if not isinstance(key, rsa.RSAPrivateKey) or not 2048 <= key.key_size <= 8192:
        raise ValueError('Expected an RSA private key between 2048 and 8192 bits.')
    return key
