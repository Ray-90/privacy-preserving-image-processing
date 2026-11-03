# Normalize images and validate pixel regions.
import io
from PIL import Image, ImageOps
from privacy_guard.config import MAX_PIXELS, MAX_BOXES


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
        raise ValueError('No detected documents, or too many boxes; no protected output created.')
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
