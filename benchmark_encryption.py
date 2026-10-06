"""Run beside encryption.py and selective.py after creating protected_sample.

python benchmark_encryption.py
Use --help to change paths. The script never saves decrypted region pixels or keys.
Timings include key-file loading and, for decryption, private-key password unlocking.
They exclude password typing, YOLO, region extraction, masking and image output.
"""
import argparse
import getpass
import json
from pathlib import Path
import statistics
import struct
import time

import encryption as enc
from selective import load_image, validate_boxes


def measure(action, repeats):
    values = []
    for _ in range(repeats):
        start = time.perf_counter()
        action()
        values.append((time.perf_counter() - start) * 1000)
    return {'mean_ms': round(statistics.mean(values), 3),
            'stddev_ms': round(statistics.stdev(values), 3),
            'minimum_ms': round(min(values), 3), 'runs': repeats}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--original', default='sample.jpg')
    parser.add_argument('--protected', default='protected_sample/protected.png')
    parser.add_argument('--regions', default='protected_sample/regions.islenc')
    parser.add_argument('--restored', default='restored.png')
    parser.add_argument('--public-key', default='keys/public.pem')
    parser.add_argument('--private-key', default='keys/private.pem')
    parser.add_argument('--runs', type=int, default=10)
    args = parser.parse_args()
    if args.runs < 2:
        parser.error('--runs must be at least 2')
    paths = [args.original, args.protected, args.regions, args.restored,
             args.public_key, args.private_key]
    for path in paths:
        if not Path(path).is_file():
            parser.error(f'File not found: {path}')
    password = getpass.getpass('Private-key password (not timed): ').encode('utf-8')
    package = enc.read_bounded(args.regions, enc.MAX_PACKAGE)
    payload = enc.decrypt_bytes(package, args.private_key, password)
    # Validate the PNG/sidecar pairing before calculating any evidence.
    length = struct.unpack('>I', payload[:4])[0]
    metadata = json.loads(payload[4:4 + length])
    if metadata.get('format') != 'ISL-ROI-1':
        raise ValueError('Expected a selective-encryption sidecar.')
    import hashlib
    if hashlib.sha256(Path(args.protected).read_bytes()).hexdigest() != metadata['preview_sha256']:
        raise ValueError('Protected image does not match the encrypted regions.')
    original = load_image(args.original)
    restored = load_image(args.restored)
    protected = load_image(args.protected)
    if not (original.size == restored.size == protected.size
            and original.mode == restored.mode == protected.mode):
        raise ValueError('Image sizes or modes differ.')
    original_bytes = original.tobytes()
    if hashlib.sha256(original_bytes).hexdigest() != metadata['original_pixels_sha256']:
        raise ValueError('Original does not match the encrypted regions.')
    restored_bytes = restored.tobytes()
    protected_bytes = protected.tobytes()
    boxes = validate_boxes(metadata['boxes'], original.size)
    width, height = original.size
    mask = bytearray(width * height)
    for x1, y1, x2, y2 in boxes:
        for y in range(y1, y2):
            mask[y * width + x1:y * width + x2] = b'\1' * (x2 - x1)
    channels = len(original.getbands())
    outside = 0
    unchanged = 0
    matching_pixels = 0
    for pixel, covered in enumerate(mask):
        start = pixel * channels
        source = original_bytes[start:start + channels]
        matching_pixels += source == restored_bytes[start:start + channels]
        if not covered:
            outside += 1
            unchanged += source == protected_bytes[start:start + channels]
    mse = sum((a - b) ** 2 for a, b in zip(original_bytes, restored_bytes)) / len(original_bytes)
    # Warm up, verifying the selected public and private keys match.
    trial = enc.encrypt_bytes(payload, args.public_key)
    if enc.decrypt_bytes(trial, args.private_key, password) != payload:
        raise ValueError('Encryption/decryption round trip failed.')
    encryption = measure(lambda: enc.encrypt_bytes(payload, args.public_key), args.runs)
    decryption = measure(lambda: enc.decrypt_bytes(trial, args.private_key, password), args.runs)
    original_size = Path(args.original).stat().st_size
    protected_size = Path(args.protected).stat().st_size
    regions_size = Path(args.regions).stat().st_size
    report = {
        'timing_scope': 'Hybrid payload operations including key loading/unlocking; excludes password entry, YOLO, cropping, masking and image output.',
        'encryption': encryption, 'decryption': decryption,
        'region_payload_bytes': len(payload),
        'original_file_bytes': original_size, 'protected_png_bytes': protected_size,
        'encrypted_region_file_bytes': regions_size,
        'total_protected_output_bytes': protected_size + regions_size,
        'storage_overhead_percent': round((protected_size + regions_size - original_size) / original_size * 100, 3),
        'restored_pixel_match_percent': round(matching_pixels / (width * height) * 100, 6),
        'restoration_mse': mse,
        'outside_region_pixel_count': outside,
        'outside_region_unchanged_percent': round(unchanged / outside * 100, 6) if outside else None,
        'outside_region_note': 'Not applicable when boxes cover the entire image.' if not outside else 'Measured against normalized original pixels.',
        'note': 'Single-image benchmark. PNG versus JPEG encoding also affects storage overhead. This run does not repeat tamper tests; use the unittest suite for those.'
    }
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, struct.error) as error:
        raise SystemExit(f'Error: {error}')
