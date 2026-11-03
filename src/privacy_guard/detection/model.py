# Lazy YOLO loading and conversion of predictions into pixel boxes.
import math
from pathlib import Path
from privacy_guard.config import CLASS_NAMES


def load_model(weights):
    try:
        from ultralytics import YOLO
    except ImportError as exc:
        raise RuntimeError('Install dependencies: python -m pip install -e ".[yolo]"') from exc
    return YOLO(str(weights))


def load_document_model(weights):
    if not Path(weights).is_file():
        raise ValueError(f'Trained weights not found: {weights}. Run train first.')
    model = load_model(weights)
    names = model.names
    values = [names[i] for i in range(len(names))] if isinstance(names, dict) else list(names)
    if values != CLASS_NAMES or model.task != 'detect':
        raise ValueError('Train on the combined dataset and use its best.pt; old Credit_card-only weights are not supported.')
    return model


def box_records(result):
    """Return clipped integer pixel rectangles suitable for image slicing."""
    height, width = result.orig_shape
    records = []
    if result.boxes is None:
        return records
    for box in result.boxes:
        x1, y1, x2, y2 = box.xyxy[0].tolist()
        x1, y1 = max(0, math.floor(x1)), max(0, math.floor(y1))
        x2, y2 = min(width, math.ceil(x2)), min(height, math.ceil(y2))
        if x2 <= x1 or y2 <= y1:
            continue
        records.append({'class_id': int(box.cls.item()), 'class_name': result.names[int(box.cls.item())],
                        'confidence': float(box.conf.item()), 'xyxy': [x1, y1, x2, y2]})
    return records
