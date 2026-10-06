# Credit-card image detection

Start with **SELECTIVE_ENCRYPTION.md** to detect cards, encrypt only their bounding-box pixels and restore them. The `selective.py protect` command connects detection and encryption.

The package also includes whole-image hybrid encryption in `encryption.py`. See **ENCRYPTION.md** for key generation, encryption, decryption and tests. It can run independently of the detector.

Python YOLOv8 nano baseline for the image-detection stage of the privacy-preserving image-processing project. This stage locates whole credit cards, saves annotated images, and exports bounding boxes and confidence scores as JSON. It does not read card numbers or encrypt images. Annotated images still contain visible card details; zero detections does not mean an image is safe.

## 1. Install

Use Python 3.10 or 3.11. Open a terminal in this extracted folder:

```sh
python -m venv .venv
```

Windows PowerShell activation: `.venv\Scripts\Activate.ps1`

macOS/Linux activation: `source .venv/bin/activate`

```sh
python -m pip install -r requirements.txt
```

Internet is needed for dependencies and the first download of yolov8n.pt. Training and prediction then run on your computer. The default is CPU; an appropriately configured CUDA installation can use `--device 0`.

## 2. Add the dataset

Download/export your Roboflow dataset in YOLOv8 format. Place the full dataset under `dataset` alongside detector.py:

| Location | Contents |
| --- | --- |
| dataset/data.yaml | Your original uploaded configuration |
| dataset/train/images | Training images |
| dataset/train/labels | Matching YOLO .txt labels |
| dataset/valid/images | Validation images |
| dataset/valid/labels | Matching YOLO .txt labels |
| dataset/test/images | Held-out test images, if provided |
| dataset/test/labels | Test labels, if provided |

Each object label row is `0 x_center y_center width height`, with coordinates normalized to 0–1. A label has the same filename stem as its image. Background images may have empty labels. Keep related images of the same card out of different splits to reduce data leakage.

The script checks the one-class configuration and expected folder structure. It creates a temporary absolute-path configuration, avoiding the ambiguous `../train/images` paths in the exported YAML without modifying your original file. It does not perform a full annotation audit; Ultralytics performs additional dataset checks during training.

## 3. Train

```sh
python detector.py train --dataset dataset --epochs 50 --batch 8
```

For a pipeline smoke run, use `--epochs 1`; that is not sufficient evidence of model quality. Lower `--batch` if memory is limited. The base model is general-purpose and must be trained on this dataset before credit-card prediction. The trained checkpoint path is printed, typically `runs/train/weights/best.pt`. Later runs may receive a numbered folder; use the printed path.

## 4. Detect cards

```sh
python detector.py predict --weights runs/train/weights/best.pt --source sample.jpg
python detector.py predict --weights runs/train/weights/best.pt --source input_images --conf 0.25
```

Each invocation creates a new results folder with an annotated PNG and JSON file per image. Original images are not modified. The confidence threshold is adjustable; it has not been calibrated for your dataset. No detections produces an empty detections list. Prediction requires a local trained checkpoint whose class is Credit_card; it rejects general-purpose checkpoints.

JSON rectangles are integer `[x1,y1,x2,y2]` coordinates clipped to the image. The right and bottom bounds are exclusive for slicing: `image[y1:y2, x1:x2]`. These rectangles can be passed to the later encryption stage. Overlapping regions will need to be merged or tracked there.

## 5. Evaluate

```sh
python detector.py evaluate --dataset dataset --weights runs/train/weights/best.pt --split test
```

If no test split exists, use `--split val` and report the result as validation performance. Evaluation prints mAP50 and mAP50–95 and writes Ultralytics evaluation outputs. Inspect precision, recall, and missed cards before integrating detection with privacy protection.

## Current verification

The delivered code has syntax, CLI, dataset-path, and bounding-box conversion checks. No actual training or inference has been performed: images, labels, trained weights, and the Ultralytics runtime were not available in the working environment. No accuracy claims are made. Dependency ranges are compatibility constraints, not a fully tested lockfile.

## References

- Ultralytics Python API: https://docs.ultralytics.com/usage/python/
- Prediction and Results API: https://docs.ultralytics.com/modes/predict/
- Dataset source (from uploaded YAML): https://universe.roboflow.com/workspace1-ttx3t/credit-card-altdh-hijjm/dataset/1

The supplied dataset metadata declares CC BY 4.0. Retain its source attribution when using the dataset.
