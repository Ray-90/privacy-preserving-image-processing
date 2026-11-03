# Save annotated predictions and structured detection records.
import json
import tempfile
from pathlib import Path
from privacy_guard.config import IMAGE_EXTENSIONS
from privacy_guard.detection.model import load_document_model, box_records


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
    model = load_document_model(args.weights)
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
        print(f'{path.name}: {len(records)} document(s)')
    print(f'Results saved to: {run}')
