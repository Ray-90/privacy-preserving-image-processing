"""Explicit SHA-256 comparison of originals and decrypted outputs."""
import hashlib
import hmac
import json
from pathlib import Path

from privacy_guard.imaging.operations import load_image


def file_sha256(path):
    """Hash exact file bytes without loading the entire file into memory."""
    digest = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def image_sha256(path):
    """Hash normalized mode, dimensions and pixels, excluding file metadata."""
    image = load_image(path)
    header = json.dumps(
        {'mode': image.mode, 'size': list(image.size)},
        sort_keys=True, separators=(',', ':')).encode('ascii')
    digest = hashlib.sha256()
    digest.update(b'privacy-guard:image-v1\0')
    digest.update(header)
    digest.update(b'\0')
    digest.update(image.tobytes())
    return digest.hexdigest()


def compare_integrity(original, restored, mode='pixels'):
    """Compare a trusted original with a restored image or decrypted file."""
    if mode not in ('pixels', 'file'):
        raise ValueError('Integrity mode must be pixels or file.')
    hash_function = image_sha256 if mode == 'pixels' else file_sha256
    original_hash = hash_function(original)
    restored_hash = hash_function(restored)
    match = hmac.compare_digest(original_hash, restored_hash)
    return {
        'algorithm': 'SHA-256',
        'mode': mode,
        'scope': ('Normalized orientation, RGB/RGBA mode, dimensions and pixels'
                  if mode == 'pixels' else 'Exact file bytes including metadata'),
        'original_sha256': original_hash,
        'restored_sha256': restored_hash,
        'match': match,
        'result': 'PASS' if match else 'FAIL',
    }
