# Training and validation workflows.
import json
import tempfile
from pathlib import Path
from privacy_guard.detection.dataset import dataset_config
from privacy_guard.detection.model import load_model, load_document_model
from privacy_guard.detection.metrics import metrics_summary


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
            model = load_document_model(args.weights)
            metrics = model.val(data=str(data), split=args.split, imgsz=args.imgsz,
                                device=args.device, workers=0,
                                project=str(Path(args.output).resolve()), name='evaluate', verbose=True)
            report = metrics_summary(metrics)
            report['split'] = args.split
            print(json.dumps(report, indent=2))
            folder = Path(args.output).resolve()
            folder.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', prefix='evaluation_',
                                             dir=folder, encoding='utf-8', delete=False) as handle:
                json.dump(report, handle, indent=2)
                print(f'Evaluation JSON: {handle.name}')
