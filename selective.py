"""Detect cards, encrypt their pixels, and restore them using an encrypted sidecar."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import struct

from PIL import Image, ImageOps
import encryption as enc

MAX_PIXELS = 12_000_000
MAX_BOXES = 1000


def load_image(path):
    with Image.open(path) as image:
        if image.width * image.height > MAX_PIXELS or getattr(image, 'n_frames', 1) != 1:
            raise ValueError('Use a single-frame image of at most 12 million pixels.')
        image = ImageOps.exif_transpose(image)
        mode = 'RGBA' if 'A' in image.getbands() or 'transparency' in image.info else 'RGB'
        # Fresh image strips metadata, including EXIF thumbnails.
        converted = image.convert(mode)
        return Image.frombytes(mode, converted.size, converted.tobytes())


def validate_boxes(boxes, size):
    if not isinstance(boxes, list) or not 1 <= len(boxes) <= MAX_BOXES:
        raise ValueError('No detected cards, or too many boxes; no protected output created.')
    width, height = size
    result = []
    for box in boxes:
        if (not isinstance(box, (list, tuple)) or len(box) != 4
                or any(type(v) is not int for v in box)):
            raise ValueError('Boxes must contain four integer pixel coordinates.')
        x1, y1, x2, y2 = box
        if not 0 <= x1 < x2 <= width or not 0 <= y1 < y2 <= height:
            raise ValueError('Box outside image or empty.')
        result.append([x1, y1, x2, y2])
    return result


def png_bytes(image):
    buffer = io.BytesIO()
    image.save(buffer, format='PNG')
    return buffer.getvalue()


def protect_image(image, boxes, output_directory, public_key):
    """All crops come from the original; overlapping boxes restore correctly."""
    if image.mode not in ('RGB', 'RGBA') or image.width * image.height > MAX_PIXELS:
        raise ValueError('Expected a normalized RGB/RGBA image within the pixel limit.')
    boxes = validate_boxes(boxes, image.size)
    channels = len(image.getbands())
    total = sum((b[2]-b[0])*(b[3]-b[1])*channels for b in boxes)
    if total > enc.MAX_PLAINTEXT - 1_000_000:
        raise ValueError('Combined regions exceed payload limit; reduce image size.')
    redacted = Image.frombytes(image.mode, image.size, image.tobytes())
    patches = []
    for box in boxes:
        patches.append(image.crop(tuple(box)).tobytes())
        redacted.paste((0, 0, 0, 255) if channels == 4 else (0, 0, 0), tuple(box))
    preview = png_bytes(redacted)
    manifest = {'format': 'ISL-ROI-1', 'mode': image.mode, 'size': list(image.size),
                'boxes': boxes, 'preview_sha256': hashlib.sha256(preview).hexdigest(),
                'original_pixels_sha256': hashlib.sha256(image.tobytes()).hexdigest()}
    metadata = json.dumps(manifest, separators=(',', ':')).encode('utf-8')
    payload = struct.pack('>I', len(metadata)) + metadata + b''.join(patches)
    encrypted = enc.encrypt_bytes(payload, public_key)
    output = Path(output_directory)
    # A fresh directory keeps each preview paired with exactly one sidecar.
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    try:
        enc.write_new(output / 'regions.islenc', encrypted)
        enc.write_new(output / 'protected.png', preview)
    except BaseException:
        for name in ['regions.islenc', 'protected.png']:
            (output / name).unlink(missing_ok=True)
        output.rmdir()
        raise
    return output


def protect_with_yolo(source, weights, public_key, output, conf=0.25, device='cpu', imgsz=640):
    from detector import require_card_model, box_records
    image = load_image(source)
    model = require_card_model(weights)
    # Infer on the exact oriented RGB pixels used for cropping, not a second file decode.
    result = model.predict(source=image.convert('RGB'), conf=conf, device=device,
                           imgsz=imgsz, verbose=False, save=False, save_txt=False,
                           save_crop=False)[0]
    if tuple(result.orig_shape) != (image.height, image.width):
        raise ValueError('Detector dimensions do not match the normalized image.')
    boxes = [record['xyxy'] for record in box_records(result)]
    return protect_image(image, boxes, output, public_key)


def restore(preview_path, regions_path, destination, private_key, password):
    if Path(destination).suffix.lower() != '.png':
        raise ValueError('Restored output must use .png for lossless pixels.')
    payload = enc.decrypt_bytes(enc.read_bounded(regions_path, enc.MAX_PACKAGE), private_key, password)
    if len(payload) < 4:
        raise ValueError('Invalid region payload.')
    length = struct.unpack('>I', payload[:4])[0]
    if not 0 < length <= 1_000_000 or len(payload) < 4 + length:
        raise ValueError('Invalid region metadata length.')
    metadata = json.loads(payload[4:4+length])
    if not isinstance(metadata, dict) or metadata.get('format') != 'ISL-ROI-1':
        raise ValueError('Unsupported region format.')
    preview = enc.read_bounded(preview_path, enc.MAX_PLAINTEXT)
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
    enc.write_new(destination, png_bytes(image))


def main():
    from detector import confidence, positive_int
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    protect = commands.add_parser('protect')
    protect.add_argument('--input', required=True)
    protect.add_argument('--weights', required=True)
    protect.add_argument('--public-key', required=True)
    protect.add_argument('--output', required=True, help='New directory with existing parent')
    protect.add_argument('--conf', type=confidence, default=0.25)
    protect.add_argument('--device', default='cpu')
    protect.add_argument('--imgsz', type=positive_int, default=640)
    decrypt = commands.add_parser('restore')
    decrypt.add_argument('--image', required=True)
    decrypt.add_argument('--regions', required=True)
    decrypt.add_argument('--private-key', required=True)
    decrypt.add_argument('--output', required=True)
    args = parser.parse_args()
    try:
        if args.command == 'protect':
            output = protect_with_yolo(args.input, args.weights, args.public_key,
                                       args.output, args.conf, args.device, args.imgsz)
            print(f'Saved {output / "protected.png"} and {output / "regions.islenc"}')
        else:
            restore(args.image, args.regions, args.output, args.private_key, enc.prompt_password())
            print(f'Restored image: {args.output}')
    except (ValueError, OSError, TypeError, KeyError, RuntimeError, ImportError, EOFError) as exc:
        parser.exit(1, f'Error: {exc}\n')


if __name__ == '__main__':
    main()
