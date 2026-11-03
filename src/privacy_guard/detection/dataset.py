# Validate the unified three-class YOLO dataset.
import math
from pathlib import Path
from privacy_guard.config import CLASS_NAMES, IMAGE_EXTENSIONS


def dataset_config(root):
    """Use an explicit dataset root; avoid ambiguous Roboflow ../ paths."""
    import yaml
    root = Path(root).expanduser().resolve()
    config = yaml.safe_load((root / 'data.yaml').read_text(encoding='utf-8'))
    if not isinstance(config, dict):
        raise ValueError('data.yaml must contain a YAML mapping.')
    names = config.get('names')
    if isinstance(names, dict):
        if set(names) != set(range(len(names))):
            raise ValueError('Class IDs must be consecutive integers starting from zero.')
        names = [names[i] for i in range(len(names))]
    if names != CLASS_NAMES:
        raise ValueError('Expected names: [aadhaar_card, pan_card, payment_card] in this order.')
    if config.get('nc', len(names)) != len(names):
        raise ValueError('nc does not match the number of class names.')
    resolved = {'path': str(root), 'nc': len(names), 'names': names}
    for split, folder in [('train', 'train'), ('val', 'valid'), ('test', 'test')]:
        images = root / folder / 'images'
        if split == 'test' and not images.exists():
            continue
        if not images.is_dir():
            raise ValueError(f'Missing images folder: {images}')
        files = [p for p in images.rglob('*') if p.suffix.lower() in IMAGE_EXTENSIONS]
        if not files:
            raise ValueError(f'No images found in {images}')
        labels = root / folder / 'labels'
        if not labels.is_dir() or not any(labels.rglob('*.txt')):
            raise ValueError(f'Missing YOLO label files in {labels}')
        resolved[split] = str(images)
    return resolved


def check_dataset(root):
    config = dataset_config(root)
    counts = {}
    for split in ['train', 'val', 'test']:
        if split not in config:
            continue
        images = Path(config[split])
        labels = images.parent / 'labels'
        totals = dict.fromkeys(CLASS_NAMES, 0)
        image_count = 0
        for image in sorted(images.rglob('*')):
            if image.suffix.lower() not in IMAGE_EXTENSIONS:
                continue
            image_count += 1
            label = labels / image.relative_to(images).with_suffix('.txt')
            if not label.is_file():
                raise ValueError(f'Missing label: {label}')
            for row_number, row in enumerate(label.read_text().splitlines(), 1):
                if not row.strip():
                    continue
                try:
                    fields = row.split()
                    if len(fields) != 5:
                        raise ValueError('Expected detection boxes, not polygons')
                    cls = int(fields[0])
                    x, y, w, h = map(float, fields[1:])
                    if cls not in range(3) or not all(math.isfinite(v) for v in [x,y,w,h]):
                        raise ValueError('Invalid class or nonfinite coordinate')
                    if w <= 0 or h <= 0 or min(x-w/2,y-h/2) < -1e-7 or max(x+w/2,y+h/2) > 1+1e-7:
                        raise ValueError('Invalid bounding box')
                    totals[CLASS_NAMES[cls]] += 1
                except ValueError as exc:
                    raise ValueError(f'{label}, row {row_number}: {exc}') from exc
        counts[split] = {'images': image_count, 'instances': totals}
    return counts
