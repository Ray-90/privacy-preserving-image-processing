"""Credit-card detection CLI. See README.md for setup and dataset layout."""
import argparse
import json
import math
from pathlib import Path
import tempfile

IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.bmp', '.webp', '.tif', '.tiff'}


def dataset_config(root):
    """Use an explicit dataset root; avoid ambiguous Roboflow ../ paths."""
    import yaml
    root = Path(root).expanduser().resolve()
    config = yaml.safe_load((root / 'data.yaml').read_text(encoding='utf-8'))
    if config.get('nc') != 1 or config.get('names') not in (
        ['Credit_card'], {0: 'Credit_card'}
    ):
        raise ValueError('Expected nc: 1 and names: [Credit_card].')
    resolved = {'path': str(root), 'nc': 1, 'names': ['Credit_card']}
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


def load_model(weights):
    try:
        from ultralytics import YOLO
    except ImportError as exc:
        raise RuntimeError('Install dependencies: python -m pip install -r requirements.txt') from exc
    return YOLO(str(weights))


def require_card_model(weights):
    if not Path(weights).is_file():
        raise ValueError(f'Trained weights not found: {weights}. Run train first.')
    model = load_model(weights)
    names = model.names
    values = list(names.values()) if isinstance(names, dict) else list(names)
    if values != ['Credit_card'] or model.task != 'detect':
        raise ValueError('Use a detection model trained on the Credit_card dataset.')
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
        records.append({'class_id': int(box.cls.item()), 'class_name': 'Credit_card',
                        'confidence': float(box.conf.item()), 'xyxy': [x1, y1, x2, y2]})
    return records


def train_or_evaluate(args):
    import yaml
    config = dataset_config(args.dataset)
    # Only a temporary copy is normalized; the supplied data.yaml stays intact.
    with tempfile.TemporaryDirectory(prefix='card_yolo_') as tmp:
        data = Path(tmp) / 'data.yaml'
        data.write_text(yaml.safe_dump(config), encoding='utf-8')
        if args.command == 'train':
            model = load_model(args.model)
            model.train(data=str(data), epochs=args.epochs, imgsz=args.imgsz,
                        batch=args.batch, device=args.device, workers=0,
                        project=str(Path(args.output).resolve()), name='train',
                        exist_ok=False, seed=42)
            print(f'Trained weights: {model.trainer.save_dir / "weights" / "best.pt"}')
        else:
            if args.split not in config:
                raise ValueError(f'Dataset has no {args.split} split.')
            model = require_card_model(args.weights)
            metrics = model.val(data=str(data), split=args.split, imgsz=args.imgsz,
                                device=args.device, workers=0,
                                project=str(Path(args.output).resolve()), name='evaluate')
            print(json.dumps({'mAP50': float(metrics.box.map50),
                              'mAP50_95': float(metrics.box.map)}, indent=2))


def predict(args):
    source = Path(args.source).expanduser().resolve()
    if source.is_file() and source.suffix.lower() in IMAGE_EXTENSIONS:
        files = [source]
    elif source.is_dir():
        files = sorted(p for p in source.rglob('*') if p.suffix.lower() in IMAGE_EXTENSIONS)
    else:
        raise ValueError('Source must be a local image or image folder.')
    if not files:
        raise ValueError('No supported images found.')
    model = require_card_model(args.weights)
    import cv2
    output = Path(args.output).expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    run = Path(tempfile.mkdtemp(prefix='predict_', dir=output))
    for index, path in enumerate(files):
        result = model.predict(source=str(path), conf=args.conf, imgsz=args.imgsz,
                               device=args.device, verbose=False)[0]
        records = box_records(result)
        stem = f'{index:05d}_{path.stem}'
        annotated = run / f'{stem}_annotated.png'
        if not cv2.imwrite(str(annotated), result.plot()):
            raise RuntimeError(f'Could not save {annotated}')
        report = {'source': str(path), 'image_size': {'width': result.orig_shape[1],
                  'height': result.orig_shape[0]}, 'confidence_threshold': args.conf,
                  'detection_count': len(records), 'detections': records,
                  'coordinate_format': 'xyxy pixels; x2/y2 exclusive for slicing'}
        (run / f'{stem}.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
        print(f'{path.name}: {len(records)} card(s)')
    print(f'Results saved to: {run}')


def positive_int(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError('Must be a positive integer.')
    return number


def confidence(value):
    number = float(value)
    if not 0 < number <= 1:
        raise argparse.ArgumentTypeError('Must be greater than 0 and at most 1.')
    return number


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    for command in ['train', 'evaluate', 'predict']:
        p = sub.add_parser(command)
        p.add_argument('--device', default='cpu', help='cpu, 0 for CUDA GPU, or mps')
        p.add_argument('--imgsz', type=positive_int, default=640)
        p.add_argument('--output', default='runs')
        if command in ['train', 'evaluate']:
            p.add_argument('--dataset', required=True, help='Folder containing data.yaml and train/valid/test')
        if command == 'train':
            p.add_argument('--model', default='yolov8n.pt')
            p.add_argument('--epochs', type=positive_int, default=50)
            p.add_argument('--batch', type=positive_int, default=8)
        else:
            p.add_argument('--weights', required=True, help='Path to trained best.pt')
        if command == 'evaluate':
            p.add_argument('--split', choices=['val', 'test'], default='test')
        if command == 'predict':
            p.add_argument('--source', required=True)
            p.add_argument('--conf', type=confidence, default=0.25)
    args = parser.parse_args()
    try:
        predict(args) if args.command == 'predict' else train_or_evaluate(args)
    except (ValueError, OSError, RuntimeError, ImportError) as exc:
        parser.exit(1, f'Error: {exc}\n')


if __name__ == '__main__':
    main()
