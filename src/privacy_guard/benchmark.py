# Measure hybrid crypto timing, restoration and storage overhead.
import json
import statistics
import struct
import time
from pathlib import Path
from privacy_guard.crypto.format import MAX_PACKAGE
from privacy_guard.crypto.hybrid import encrypt_bytes, decrypt_bytes
from privacy_guard.crypto.image_password import protect_payload, unlock_payload
from privacy_guard.file_io import read_bounded
from privacy_guard.imaging.operations import load_image, validate_boxes

def measure(action, repeats):
    values = []
    for _ in range(repeats):
        start = time.perf_counter()
        action()
        values.append((time.perf_counter() - start) * 1000)
    return {'mean_ms': round(statistics.mean(values), 3),
            'stddev_ms': round(statistics.stdev(values), 3),
            'minimum_ms': round(min(values), 3), 'runs': repeats}

def run_benchmark(args, password, image_password):
    if args.runs < 2:
        raise ValueError('--runs must be at least 2')
    paths = [args.original, args.protected, args.regions, args.restored,
             args.public_key, args.private_key]
    for path in paths:
        if not Path(path).is_file():
            raise ValueError(f'File not found: {path}')
    package = read_bounded(args.regions, MAX_PACKAGE)
    payload = unlock_payload(decrypt_bytes(package, args.private_key, password), image_password)
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
    trial = encrypt_bytes(protect_payload(payload, image_password), args.public_key)
    if unlock_payload(decrypt_bytes(trial, args.private_key, password), image_password) != payload:
        raise ValueError('Encryption/decryption round trip failed.')
    encryption = measure(lambda: encrypt_bytes(protect_payload(payload, image_password), args.public_key), args.runs)
    decryption = measure(lambda: unlock_payload(decrypt_bytes(trial, args.private_key, password), image_password), args.runs)
    original_size = Path(args.original).stat().st_size
    protected_size = Path(args.protected).stat().st_size
    regions_size = Path(args.regions).stat().st_size
    report = {
        'timing_scope': 'Password-derived image layer and hybrid payload operations including key loading/unlocking; excludes password entry, YOLO, cropping, masking and image output.',
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
    return report
