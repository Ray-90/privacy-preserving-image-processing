"""Bounded image inspection and verifiable protection checks; no metadata values logged."""
from datetime import datetime, timezone
import hashlib
import io
from pathlib import Path

from PIL import Image, ImageChops, ImageDraw

from privacy_guard.config import MAX_PIXELS
from privacy_guard.crypto.format import MAX_PLAINTEXT
from privacy_guard.file_io import read_bounded
from privacy_guard.imaging.operations import load_image, validate_boxes

EXTENSIONS = {
    'JPEG': {'.jpg', '.jpeg'}, 'PNG': {'.png'}, 'WEBP': {'.webp'},
    'BMP': {'.bmp'}, 'TIFF': {'.tif', '.tiff'},
}


def signature_format(data):
    if data.startswith(b'\x89PNG\r\n\x1a\n'):
        return 'PNG'
    if data.startswith(b'\xff\xd8\xff'):
        return 'JPEG'
    if data[:4] == b'RIFF' and data[8:12] == b'WEBP':
        return 'WEBP'
    if data.startswith(b'BM'):
        return 'BMP'
    if data[:4] in (b'II*\x00', b'MM\x00*', b'II+\x00', b'MM\x00+'):
        return 'TIFF'
    raise ValueError('Unsupported image signature; use JPEG, PNG, WebP, BMP or TIFF.')


def inspect_bytes(data, suffix):
    detected = signature_format(data)
    if suffix.lower() not in EXTENSIONS[detected]:
        raise ValueError(f'File extension does not match its {detected} signature.')
    with Image.open(io.BytesIO(data)) as image:
        if image.format != detected:
            raise ValueError('File signature and decoded format disagree.')
        if image.width * image.height > MAX_PIXELS or getattr(image, 'n_frames', 1) != 1:
            raise ValueError('Use a single-frame image of at most 12 million pixels.')
        exif = image.getexif()
        metadata = {
            'exif_present': bool(exif) or bool(image.info.get('exif')),
            'gps_tag_present': 34853 in exif,
            'icc_profile_present': bool(image.info.get('icc_profile')),
            'text_or_comment_present': bool(getattr(image, 'text', {})) or 'comment' in image.info,
            'xmp_present': any('xmp' in str(key).lower() for key in image.info),
            'any_decoder_metadata_present': bool(image.info) or bool(exif),
        }
        properties = {'format': detected, 'width': image.width, 'height': image.height,
                      'mode': image.mode, 'frames': 1}
    # Verify container structure, then fully decode the same bounded byte snapshot.
    with Image.open(io.BytesIO(data)) as image:
        image.verify()
    normalized = load_image(io.BytesIO(data))
    return normalized, {
        'schema': 'ISL-FORENSICS-1',
        'inspected_at_utc': datetime.now(timezone.utc).isoformat(),
        'source': 'file_bytes',
        'file_size_bytes': len(data),
        'file_sha256': hashlib.sha256(data).hexdigest(),
        'properties': properties,
        'metadata_presence': metadata,
        'extension_matches_signature': True,
        'decode_passed': True,
        'normalized_pixels_sha256': hashlib.sha256(normalized.tobytes()).hexdigest(),
        'scope': 'Decoder-based inspection; not malware scanning or proof of prior authenticity.',
    }


def inspect_image(path):
    """Inspect and normalize exactly the same immutable source bytes."""
    data = read_bounded(path, MAX_PLAINTEXT)
    return inspect_bytes(data, Path(path).suffix)


def verify_protected_image(original, preview, boxes):
    """Compare decoded output pixels outside the union of protected rectangles."""
    boxes = validate_boxes(boxes, original.size)
    with Image.open(io.BytesIO(preview)) as image:
        image.load()
        if image.format != 'PNG' or image.mode != original.mode or image.size != original.size:
            raise ValueError('Protected image format, mode or dimensions mismatch.')
        metadata_absent = not image.info and not image.getexif()
        if not metadata_absent:
            raise ValueError('Protected PNG retains decoder-visible metadata.')
        protected = image.copy()
    outside = Image.new('L', original.size, 255)
    draw = ImageDraw.Draw(outside)
    for x1, y1, x2, y2 in boxes:
        draw.rectangle((x1, y1, x2 - 1, y2 - 1), fill=0)
    # Check every channel, including alpha; RGBA getbbox alone can miss RGB changes.
    for channel in ImageChops.difference(original, protected).split():
        if ImageChops.multiply(channel, outside).getbbox() is not None:
            raise ValueError('Pixels outside protected regions were modified.')
    return {
        'outside_region_pixel_count': outside.histogram()[255],
        'outside_region_unchanged': True,
        'protected_decoder_metadata_absent': True,
        'protected_png_sha256': hashlib.sha256(preview).hexdigest(),
    }
