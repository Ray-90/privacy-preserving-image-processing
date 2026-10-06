# Bounding-box-only encryption

`selective.py` joins YOLO detection and hybrid encryption in one command. For each detected card, it extracts the pixels from the original normalized image, then covers that rectangle with opaque black pixels in a PNG. It encrypts the coordinates and original region pixels together using AES-256-GCM, with the AES key wrapped using RSA-OAEP-SHA256.

## Setup

Install `requirements.txt` and train the detector as described in README.md. Generate keys once (skip if you already have your keys):

```sh
python encryption.py keygen --directory keys
```

## Detect and protect

```sh
python selective.py protect --input sample.jpg --weights runs/train/weights/best.pt --public-key keys/public.pem --output protected_sample
```

Use the actual checkpoint path printed by training. The output directory must be new, and its parent must exist. Options include `--conf 0.25`, `--device cpu` (or `0` for a configured CUDA GPU), and `--imgsz 640`.

Two files are created:

| File | Purpose |
| --- | --- |
| protected_sample/protected.png | Viewable image with detected card rectangles blacked out |
| protected_sample/regions.islenc | Encrypted pixels, coordinates and integrity metadata |

The public image keeps pixels outside the rectangles unchanged relative to the normalized source. The sidecar contains only region pixels and restoration metadata, not a full copy of the image. Keep both files together and do not re-save the PNG: the sidecar authenticates its exact bytes. Card locations remain visually apparent from the black rectangles.

## Restore

```sh
python selective.py restore --image protected_sample/protected.png --regions protected_sample/regions.islenc --private-key keys/private.pem --output restored.png
```

Enter the private-key password when prompted. The encrypted sidecar is authenticated before use; the protected PNG hash must match. Region pixels are pasted back at their saved coordinates. A final hash verifies the recovered pixels before the restored PNG is written. Existing output files are never overwritten.

## Important behavior

- Multiple cards and overlapping boxes are supported. Every crop comes from the original image before masking, so overlapping patches contain identical original pixels where they overlap.
- EXIF orientation is applied before detection and cropping. Images are normalized to 8-bit RGB/RGBA, with opaque black masks even for images with alpha channels. Image metadata, including embedded thumbnails, is stripped from output.
- Recovery is pixel-exact relative to that oriented, normalized image. It does not reproduce the original JPEG file bytes, EXIF metadata, palette or higher-bit-depth image representation. Use whole-file encryption if original file-byte recovery is required.
- With no detected boxes, protection stops without creating output. A missed card or incomplete bounding box can leave sensitive pixels visible. Inspect detection quality; detection is not a guarantee of privacy.
- Only one single-frame image is accepted per command. Limit: 12 million pixels; combined crop bytes plus metadata must fit the 64 MiB encryption payload limit. Many overlapping boxes can reach the limit earlier.
- The protect command does not save unmasked crops or annotated previews. The original input and any files created by earlier detector commands remain on disk.
- Coordinates and hashes are encrypted inside the sidecar. The outer hybrid-encryption format and its lack of sender authentication are described in ENCRYPTION.md.

## Testing and current status

```sh
python -m unittest discover -v
```

All 16 tests passed: eight for whole-file encryption and eight for selective encryption. Selective checks cover unchanged outside pixels, overlapping regions, RGB/RGBA recovery, no detections, invalid boxes, tampered images/sidecars, overwrite refusal and orientation/metadata handling. The YOLO adapter was exercised with a test double. Real inference still requires your trained Credit_card checkpoint and dataset; no detection accuracy or full real-model pipeline result has been claimed.

Pillow orientation reference: https://pillow.readthedocs.io/en/stable/reference/ImageOps.html#PIL.ImageOps.exif_transpose
