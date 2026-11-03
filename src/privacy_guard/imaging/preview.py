"""Optional local inpainting of an already redacted preview."""
from PIL import Image


def texture_redacted(redacted, boxes):
    """Copy clean background texture into large boxes without using hidden pixels."""
    import numpy as np

    canvas = np.array(redacted.convert('RGB'), dtype=np.uint8, copy=True)
    source = canvas.copy()  # All boxes were blacked out before this function was called.
    height, width = source.shape[:2]

    def clean(x, y, w, h):
        return all(x + w <= a or x >= c or y + h <= b or y >= d
                   for a, b, c, d in boxes)

    for x1, y1, x2, y2 in boxes:
        w, h = x2 - x1, y2 - y1
        border = []
        border_positions = []
        if x1 and clean(x1 - 1, y1, 1, h):
            border.append(source[y1:y2, x1 - 1])
            border_positions.append(np.column_stack((np.full(h, x1 - 1), np.arange(y1, y2))))
        if x2 < width and clean(x2, y1, 1, h):
            border.append(source[y1:y2, x2])
            border_positions.append(np.column_stack((np.full(h, x2), np.arange(y1, y2))))
        if y1 and clean(x1, y1 - 1, w, 1):
            border.append(source[y1 - 1, x1:x2])
            border_positions.append(np.column_stack((np.arange(x1, x2), np.full(w, y1 - 1))))
        if y2 < height and clean(x1, y2, w, 1):
            border.append(source[y2, x1:x2])
            border_positions.append(np.column_stack((np.arange(x1, x2), np.full(w, y2))))
        if border:
            background = np.median(np.concatenate(border), axis=0)
        else:
            background = np.array([0, 0, 0], dtype=np.float64)

        # Fit the broad background color/lighting from the clean perimeter.
        # The copied patch contributes texture, while this plane follows local
        # gradients (for example, light falling across a desk).
        if len(border) >= 2:
            coords = np.concatenate(border_positions)
            basis = np.column_stack((np.ones(len(coords)), coords[:, 0] / width,
                                     coords[:, 1] / height))
            plane = np.linalg.lstsq(basis, np.concatenate(border).astype(np.float64),
                                    rcond=None)[0]
        else:
            plane = np.array([background, np.zeros(3), np.zeros(3)])
        target_plane = (plane[0] + (np.arange(x1, x2)[None, :, None] / width) * plane[1]
                        + (np.arange(y1, y2)[:, None, None] / height) * plane[2])

        tile = None
        # Prefer an intact patch the size of the box. If there is not enough
        # unmasked space, use a smaller clean tile with mirrored edges.
        for divisor in (1, 2, 4, 8):
            tw, th = max(1, w // divisor), max(1, h // divisor)
            xs = set(int(v) for v in np.linspace(0, width - tw, min(13, width - tw + 1)))
            ys = set(int(v) for v in np.linspace(0, height - th, min(13, height - th + 1)))
            xs.update(max(0, min(width - tw, v)) for v in (x1 - tw, x2, x1))
            ys.update(max(0, min(height - th, v)) for v in (y1 - th, y2, y1))
            best = None
            for y in ys:
                for x in xs:
                    if not clean(x, y, tw, th):
                        continue
                    candidate = source[y:y + th, x:x + tw]
                    sample = candidate[::max(1, th // 32), ::max(1, tw // 32)]
                    color_error = np.abs(sample.mean(axis=(0, 1)) - background).mean()
                    distance = (abs(x - x1) + abs(y - y1)) / max(width, height)
                    score = color_error + distance
                    if best is None or score < best[0]:
                        best = score, candidate
            if best is not None:
                tile = best[1]
                break

        if tile is None:
            fill = np.clip(target_plane, 0, 255).astype(np.uint8)
        else:
            th, tw = tile.shape[:2]
            step_y, step_x = max(1, th // 32), max(1, tw // 32)
            sample = tile[::step_y, ::step_x].astype(np.float64)
            sample_y, sample_x = np.mgrid[0:th:step_y, 0:tw:step_x]
            sample_basis = np.column_stack((np.ones(sample_y.size),
                                            sample_x.ravel() / tw, sample_y.ravel() / th))
            tile_plane = np.linalg.lstsq(sample_basis, sample.reshape(-1, 3), rcond=None)[0]
            tile_trend = (tile_plane[0] + (np.arange(tw)[None, :, None] / tw) * tile_plane[1]
                          + (np.arange(th)[:, None, None] / th) * tile_plane[2])
            texture = tile.astype(np.float32) - tile_trend.astype(np.float32)
            mirrored = np.concatenate((texture, texture[:, ::-1]), axis=1)
            mirrored = np.concatenate((mirrored, mirrored[::-1]), axis=0)
            repeated = np.tile(mirrored, ((h + len(mirrored) - 1) // len(mirrored),
                                          (w + mirrored.shape[1] - 1) // mirrored.shape[1], 1))[:h, :w]
            fill = np.clip(target_plane + repeated, 0, 255).astype(np.uint8)

        # Feather only the narrow seam. The centre keeps the copied texture.
        seam = min(5, w // 4, h // 4)
        if seam:
            for offset in range(seam):
                weight = (offset + 1) / (seam + 1)
                if x1 and clean(x1 - 1, y1, 1, h):
                    fill[:, offset] = np.uint8((1 - weight) * source[y1:y2, x1 - 1]
                                               + weight * fill[:, offset])
                if x2 < width and clean(x2, y1, 1, h):
                    fill[:, w - offset - 1] = np.uint8((1 - weight) * source[y1:y2, x2]
                                                       + weight * fill[:, w - offset - 1])
                if y1 and clean(x1, y1 - 1, w, 1):
                    fill[offset, :] = np.uint8((1 - weight) * source[y1 - 1, x1:x2]
                                               + weight * fill[offset, :])
                if y2 < height and clean(x1, y2, w, 1):
                    fill[h - offset - 1, :] = np.uint8((1 - weight) * source[y2, x1:x2]
                                                       + weight * fill[h - offset - 1, :])

        patch = Image.fromarray(fill, mode='RGB')
        if redacted.mode == 'RGBA':
            patch = patch.convert('RGBA')
        redacted.paste(patch, (x1, y1))
    return redacted


def inpaint_redacted(redacted, boxes):
    """Fill only masked boxes, never submitting original box pixels to OpenCV."""
    try:
        import cv2
        import numpy as np
    except ImportError as exc:
        raise RuntimeError('Inpainting needs OpenCV and NumPy: pip install -e ".[yolo,test]"') from exc

    # The source was blacked out by the caller before reaching this function.
    pixels = np.array(redacted.convert('RGB'), dtype=np.uint8, copy=True)
    mask = np.zeros((redacted.height, redacted.width), dtype=np.uint8)
    for x1, y1, x2, y2 in boxes:
        mask[y1:y2, x1:x2] = 255
    generated = cv2.inpaint(pixels, mask, 3, cv2.INPAINT_TELEA)
    if (not isinstance(generated, np.ndarray) or generated.dtype != np.uint8
            or generated.shape != pixels.shape):
        raise ValueError('Invalid inpainting result.')

    replacement = Image.fromarray(generated, mode='RGB')
    # Keep *all* outside pixels byte-for-byte, including alpha. OpenCV may touch
    # the wider canvas, so use only its generated pixels inside the boxes.
    for box in boxes:
        patch = replacement.crop(tuple(box))
        if redacted.mode == 'RGBA':
            patch = patch.convert('RGBA')  # Opaque, as with the original black mask.
        redacted.paste(patch, tuple(box))
    return redacted
