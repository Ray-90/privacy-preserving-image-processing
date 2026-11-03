"""Second, per-image encryption layer for selective image payloads."""
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


MAGIC = b'ISLPWD01'
HEADER_LENGTH = len(MAGIC) + 16 + 12
AAD_PURPOSE = b'privacy-guard:image-payload:v1:'


def _key(password, salt):
    if not isinstance(password, bytes) or len(password) < 8:
        raise ValueError('Image password must be at least 8 UTF-8 bytes.')
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password)


def protect_payload(payload, image_password):
    salt = os.urandom(16)
    nonce = os.urandom(12)
    header = MAGIC + salt + nonce
    return header + AESGCM(_key(image_password, salt)).encrypt(
        nonce, payload, AAD_PURPOSE + header)


def unlock_payload(package, image_password):
    if len(package) < HEADER_LENGTH + 16 or package[:len(MAGIC)] != MAGIC:
        raise ValueError('Encrypted image requires the current image-password format.')
    salt = package[len(MAGIC):len(MAGIC) + 16]
    nonce = package[len(MAGIC) + 16:HEADER_LENGTH]
    try:
        return AESGCM(_key(image_password, salt)).decrypt(
            nonce, package[HEADER_LENGTH:], AAD_PURPOSE + package[:HEADER_LENGTH])
    except InvalidTag as exc:
        raise ValueError('Incorrect image password or damaged encrypted image.') from exc
