# Detection, region encryption, masking and authenticated restoration.
import hashlib
import io
import json
import re
import struct
from pathlib import Path
from PIL import Image
from privacy_guard.config import MAX_PIXELS
from privacy_guard.crypto.format import MAX_PLAINTEXT, MAX_PACKAGE
from privacy_guard.crypto.hybrid import encrypt_bytes, decrypt_bytes
from privacy_guard.crypto.image_password import MAGIC as PASSWORD_MAGIC, protect_payload, unlock_payload
from privacy_guard.file_io import read_bounded, write_new
from privacy_guard.imaging.operations import load_image, validate_boxes, png_bytes
from privacy_guard.imaging.preview import inpaint_redacted, texture_redacted
from privacy_guard.detection.model import load_document_model, box_records
from privacy_guard.forensics import inspect_image, verify_protected_image


IMAGE_ID = re.compile(r'img-[0-9a-f]{32}\Z')


def protect_image(image, boxes, output_directory, public_key, *, image_password, inspection=None,
                  fill='black', image_id=None):
    """All crops come from the original; overlapping boxes restore correctly."""
    if image.mode not in ('RGB', 'RGBA') or image.width * image.height > MAX_PIXELS:
        raise ValueError('Expected a normalized RGB/RGBA image within the pixel limit.')
    boxes = validate_boxes(boxes, image.size)
    if fill not in ('black', 'inpaint', 'texture'):
        raise ValueError('Preview fill must be black, inpaint or texture.')
    if image_id is not None and (not isinstance(image_id, str) or not IMAGE_ID.fullmatch(image_id)):
        raise ValueError('Invalid authenticated image ID.')
    channels = len(image.getbands())
    total = sum((b[2]-b[0])*(b[3]-b[1])*channels for b in boxes)
    if total > MAX_PLAINTEXT - 1_000_000:
        raise ValueError('Combined regions exceed payload limit; reduce image size.')
    redacted = Image.frombytes(image.mode, image.size, image.tobytes())
    patches = []
    for box in boxes:
        patches.append(image.crop(tuple(box)).tobytes())
        redacted.paste((0, 0, 0, 255) if channels == 4 else (0, 0, 0), tuple(box))
    if fill == 'inpaint':
        redacted = inpaint_redacted(redacted, boxes)
    elif fill == 'texture':
        redacted = texture_redacted(redacted, boxes)
    preview = png_bytes(redacted)
    checks = verify_protected_image(image, preview, boxes)
    if inspection is None:
        inspection = {'source': 'in_memory_pixels', 'file_inspection_available': False}
    elif inspection.get('normalized_pixels_sha256') != hashlib.sha256(image.tobytes()).hexdigest():
        raise ValueError('Inspection record does not match the image pixels.')
    forensic_record = {'input_inspection': inspection, 'protection_checks': checks,
                       'preview_fill': fill}
    manifest = {'format': 'ISL-ROI-1', 'mode': image.mode, 'size': list(image.size),
                'boxes': boxes, 'preview_sha256': hashlib.sha256(preview).hexdigest(),
                'original_pixels_sha256': hashlib.sha256(image.tobytes()).hexdigest()}
    if image_id is not None:
        manifest['image_id'] = image_id
    manifest['forensics'] = forensic_record
    metadata = json.dumps(manifest, separators=(',', ':')).encode('utf-8')
    if len(metadata) > 1_000_000:
        raise ValueError('Region metadata exceeds supported size limit.')
    payload = struct.pack('>I', len(metadata)) + metadata + b''.join(patches)
    encrypted = encrypt_bytes(protect_payload(payload, image_password), public_key)
    output = Path(output_directory)
    # A fresh directory keeps each preview paired with exactly one sidecar.
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    try:
        write_new(output / 'regions.islenc', encrypted)
        write_new(output / 'protected.png', preview)
        report = {'stage': 'protection', 'forensics': forensic_record,
                  'encrypted_sidecar_sha256': hashlib.sha256(encrypted).hexdigest(),
                  'notice': 'Readable copy only. The authenticated record is inside regions.islenc.'}
        write_new(output / 'forensic_report.json', json.dumps(report, indent=2).encode('utf-8'))
    except BaseException:
        for name in ['regions.islenc', 'protected.png', 'forensic_report.json']:
            (output / name).unlink(missing_ok=True)
        output.rmdir()
        raise
    return output


def check_source_is_removable(source):
    """Refuse to consume links, training data, or an existing protected preview."""
    source = Path(source)
    if source.is_symlink() or source.stat().st_nlink != 1:
        raise ValueError('Choose a regular image file, not a link or hard link.')
    if any(parent.name == 'dataset' for parent in source.resolve().parents):
        raise ValueError('Copy a training image outside dataset/ before protecting it.')
    if source.name == 'protected.png' and (source.parent / 'regions.islenc').exists():
        raise ValueError('Do not protect a saved preview; select the original image.')


def remove_original_after_protection(source, bundle):
    """Consume exactly the input inspected for the newly written encrypted bundle."""
    source, bundle = Path(source), Path(bundle)
    check_source_is_removable(source)
    report = json.loads(read_bounded(bundle / 'forensic_report.json', 1_000_000))
    expected_input = report['forensics']['input_inspection']['file_sha256']
    expected_preview = report['forensics']['protection_checks']['protected_png_sha256']
    expected_sidecar = report['encrypted_sidecar_sha256']
    if (hashlib.sha256(read_bounded(source, MAX_PLAINTEXT)).hexdigest() != expected_input
            or hashlib.sha256(read_bounded(bundle / 'protected.png', MAX_PLAINTEXT)).hexdigest() != expected_preview
            or hashlib.sha256(read_bounded(bundle / 'regions.islenc', MAX_PACKAGE)).hexdigest() != expected_sidecar):
        raise ValueError('Source or saved encrypted output changed; original was kept.')
    try:
        source.unlink()
    except OSError as exc:
        raise OSError(f'Protected output was saved, but original could not be removed: {source}') from exc


def protect_with_yolo(source, weights, public_key, output, conf=0.25, device='cpu', imgsz=640,
                      *, image_password, fill='black', image_id=None, defer_source_removal=False):
    check_source_is_removable(source)
    image, inspection = inspect_image(source)
    model = load_document_model(weights)
    # Infer on the exact oriented RGB pixels used for cropping, not a second file decode.
    result = model.predict(source=image.convert('RGB'), conf=conf, device=device,
                           imgsz=imgsz, verbose=False, save=False, save_txt=False,
                           save_crop=False)[0]
    if tuple(result.orig_shape) != (image.height, image.width):
        raise ValueError('Detector dimensions do not match the normalized image.')
    boxes = [record['xyxy'] for record in box_records(result)]
    result = protect_image(image, boxes, output, public_key, inspection=inspection,
                           fill=fill, image_id=image_id, image_password=image_password)
    if not defer_source_removal:
        try:
            remove_original_after_protection(source, result)
        except (OSError, ValueError) as exc:
            raise RuntimeError(f'Protected bundle saved at {result}, but the selected '
                               f'original was retained: {exc}') from exc
    return result


def restore(preview_path, regions_path, destination, private_key, password,
            *, image_password, expected_image_id=None):
    if Path(destination).suffix.lower() != '.png':
        raise ValueError('Restored output must use .png for lossless pixels.')
    payload = decrypt_bytes(read_bounded(regions_path, MAX_PACKAGE), private_key, password)
    password_protected = payload.startswith(PASSWORD_MAGIC)
    if password_protected:
        payload = unlock_payload(payload, image_password)
    if len(payload) < 4:
        raise ValueError('Invalid region payload.')
    length = struct.unpack('>I', payload[:4])[0]
    if not 0 < length <= 1_000_000 or len(payload) < 4 + length:
        raise ValueError('Invalid region metadata length.')
    metadata = json.loads(payload[4:4+length])
    if not isinstance(metadata, dict) or metadata.get('format') != 'ISL-ROI-1':
        raise ValueError('Unsupported region format.')
    if expected_image_id is not None:
        if not isinstance(expected_image_id, str) or not IMAGE_ID.fullmatch(expected_image_id):
            raise ValueError('Invalid image ID.')
        if metadata.get('image_id') != expected_image_id:
            raise ValueError('Encrypted image ID does not match this folder.')
    preview = read_bounded(preview_path, MAX_PLAINTEXT)
    if hashlib.sha256(preview).hexdigest() != metadata.get('preview_sha256'):
        raise ValueError('Preview was changed or does not match this encrypted sidecar.')
    with Image.open(io.BytesIO(preview)) as loaded:
        if loaded.width * loaded.height > MAX_PIXELS:
            raise ValueError('Preview exceeds pixel limit.')
        if loaded.mode not in ('RGB', 'RGBA'):
            raise ValueError('Unsupported preview mode.')
        image = loaded.copy()
    if list(image.size) != metadata.get('size') or image.mode != metadata.get('mode'):
        raise ValueError('Preview dimensions or mode mismatch.')
    boxes = validate_boxes(metadata.get('boxes'), image.size)
    offset = 4 + length
    for x1, y1, x2, y2 in boxes:
        count = (x2-x1)*(y2-y1)*len(image.getbands())
        patch = payload[offset:offset+count]
        if len(patch) != count:
            raise ValueError('Truncated region pixels.')
        image.paste(Image.frombytes(image.mode, (x2-x1, y2-y1), patch), (x1, y1))
        offset += count
    if offset != len(payload):
        raise ValueError('Unexpected trailing region data.')
    if hashlib.sha256(image.tobytes()).hexdigest() != metadata.get('original_pixels_sha256'):
        raise ValueError('Restored pixel integrity check failed.')
    checks = verify_protected_image(image, preview, boxes)
    write_new(destination, png_bytes(image))
    return {'stage': 'restoration', 'aes_gcm_authentication': 'PASS',
            'image_password_authentication': 'PASS' if password_protected else 'not_present',
            'authenticated_image_id': metadata.get('image_id'),
            'image_id_binding_status': 'bound' if 'image_id' in metadata else 'legacy_unbound',
            'preview_sha256_match': True, 'restored_pixel_sha256_match': True,
            'protection_checks': checks,
            'authenticated_forensic_record': metadata.get('forensics'),
            'forensic_record_status': 'present' if 'forensics' in metadata else 'legacy_not_recorded',
            'notice': 'Exported JSON is not signed; this describes checks performed during this restore.'}
