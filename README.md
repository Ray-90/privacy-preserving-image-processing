# Privacy Guard

**The desktop window uses two tabs:** **Protect an
image** and **Saved images & restore**. The first shows key and model readiness,
photo selection, a description of each preview style, and a clear reminder that
the selected original is removed after successful protection. The second shows
the saved-image list, a protected preview, full ID, restoration and confirmed deletion.
The image-password and private-key-password prompts now explain which password
is needed. Incorrect passwords display an error without writing a restored image.
Successful protection opens the saved-images tab with the new image selected;
status messages stay visible at the bottom. The encrypted file format is unchanged.

**Version 1.7.0 adds `texture` as a preview fill option.** It copies pixels
only from clean, unmasked background around the detected boxes, matches the
surrounding lighting and blends the seams. This avoids the broad blur that
OpenCV inpainting can produce for a large card. Choose `texture` in the GUI,
select **2** in the terminal menu, or use `--fill texture` with `protect` or
`image-add`. It works best with a plain or consistently textured surface;
complex scenes can still show a patch or repetition. The default remains
`black` and the previous `inpaint` mode remains available. Existing protected
previews cannot be changed after encryption because their exact hashes are
authenticated inside the sidecar.

**Version 1.6.2 allows an image password of at least 8 characters** in the GUI,
terminal menu and CLI. This is a minimum, not a strength target: use a longer,
unique and hard-to-guess password for real documents. The private-key password
is still separate. Older protected images retain their original passwords.

The window gives separate messages for a password that is too short and two
entries that do not match.

**Version 1.6.0 keeps the existing-photo workflow and runs each protection in a
short-lived child process.** The GUI, terminal menu, `image-add`, and `protect`
start a worker that handles the original image, YOLO detection, and encryption.
The worker returns only the saved image ID or success status, then exits. The
desktop window handles the source path and image password but does not decode
the original pixels. Passwords are sent to the worker over stdin, not command
arguments. On Windows, image protection refuses an elevated administrator
session; open VS Code normally as a standard user. Every successful protection confirms that the selected source path
is absent. If removal fails, the app reports the location of the saved protected
bundle and that the original was retained.

No new plaintext image file is created by this protection workflow: the worker
decodes and passes pixels to YOLO in memory, then writes the encrypted sidecar
and redacted preview. The app warns when an input appears to be under OneDrive,
Dropbox, Google Drive, iCloud Drive, or Box. This is a best-effort warning;
other sync locations and existing cloud copies may not be detectable.
Process isolation reduces the time plaintext pixels are in a running process.
It cannot guarantee removal of every RAM/GPU copy, pagefile entry, old deleted
file remnant, thumbnail, or backup. An attacker who can read the worker while
it runs may still obtain the image. This update does not add a camera capture
feature.

**Version 1.5.0 asks you to create and repeat an image password whenever you
protect an image.** The local desktop window and terminal menu both do this;
the `protect` and `image-add` commands prompt too. Use a different long password
for each image and keep it in a password manager. Restoring a newly protected
image requires both its image password and the password for your existing RSA
private key. Image passwords are never saved in the image folder. Random salts
make encryption different for each image, but the app cannot tell whether you
reuse the same password text.

The desktop window manages images using local random IDs and no database.
The ID is a convenient folder name, not an account or access-control system.

**Protection removes the selected source file after the protected bundle has
been saved and read back.** This applies to the desktop window, terminal menu,
`image-add`, `protect`, and the whole-file `encrypt` command. Failed
protection keeps the source. Back up your private key and each image password
before using this mode: losing either means that image cannot be restored.
Select a test image outside `dataset/`; inputs inside that folder are refused
to avoid deleting training images. Existing source files from earlier runs are not
automatically found or deleted. This is ordinary deletion, not secure erasure
from SSD remnants, synced folders, or backups.

**Easiest way to run it:** After installing below, open PowerShell in this
project folder and run `.\.venv\Scripts\python.exe gui.py`. The window lets you
create keys, choose and protect an image, list saved encryptions, view a
protected preview, restore a selected image to a PNG location you choose, or
delete one saved entry after confirmation. Incorrect passwords show an error;
failed restoration does not create a restored PNG.
Everything runs locally. The terminal menu is still available with
`.\.venv\Scripts\python.exe app.py`.

Set `MODEL_WEIGHTS` near the top of `app.py` once to your trained three-class
`best.pt`. The default is `runs/train-2/weights/best.pt`; if it was saved elsewhere,
use a raw Windows path such as
`Path(r'C:\Users\you\Downloads\IS\runs\train2\weights\best.pt')`.
The window and terminal menu use that same model for every image. Encrypted
bundles are saved under `protected_images/`.

The window offers `black`, `texture`, or `inpaint` for the hidden area. The menu
uses the same three choices. Inpainting
is a local image-processing algorithm, not a generative AI model; large card
areas may look artificial. The actual sensitive box pixels are captured for
AES-GCM encryption, then blacked out **before** OpenCV receives the image.
Generated colors are pasted only inside detected boxes, so outside pixels stay
unchanged. The finished preview's SHA-256 hash is authenticated inside the
encrypted sidecar. Restoration replaces the generated colors with the real
original pixels. Do not inpaint `protected.png` after saving it: that would
invalidate the authenticated preview hash. OpenCV comes from the `[yolo]`
installation extra used in Setup below.

Texture fill uses only pixels from the already blacked-out image and avoids
sampling any masked boxes. Its broad color gradient comes from clean pixels
outside the box. It does not reconstruct what was behind the document and does
not use a generative model or upload any image. If there is no clean background
to sample, it falls back to a flat local color or black.

Detect Aadhaar, PAN and payment cards using a trained YOLO model; encrypt only
their bounding-box pixels; restore them with the matching private key, private-key
password and image password.

## Setup in VS Code (Windows PowerShell)

Extract this project into its own folder and open that folder in VS Code.
Create the virtual environment once:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[yolo,test]"
```

Use **Python: Select Interpreter** in the VS Code command palette and select
`.venv\Scripts\python.exe`. Activate it in your terminal:

```powershell
.\.venv\Scripts\Activate.ps1
python -m privacy_guard --help
```

If PowerShell blocks activation, use `.\.venv\Scripts\python.exe` in place
of `python` in the commands below. Activation is optional.

For encryption-only use, install with `python -m pip install -e .`.
YOLO is an optional dependency, loaded only when detection/training needs it.
The convenience command `privacy-guard` is equivalent to
`python -m privacy_guard` when the environment is activated.

## Module guide

| Path | Responsibility |
| --- | --- |
| `src/privacy_guard/cli.py` | Parse all commands, prompt for passwords, dispatch workflows |
| `src/privacy_guard/config.py` | Shared class names and image limits |
| `src/privacy_guard/detection/dataset.py` | Validate dataset layout, class IDs and box labels |
| `src/privacy_guard/detection/model.py` | Load YOLO, require correct classes, convert boxes to pixels |
| `src/privacy_guard/detection/training.py` | Train and evaluate models |
| `src/privacy_guard/detection/metrics.py` | Overall and per-class evaluation metrics |
| `src/privacy_guard/detection/prediction.py` | Annotated images and detection JSON |
| `src/privacy_guard/crypto/keys.py` | RSA key generation/loading and OAEP padding |
| `src/privacy_guard/crypto/hybrid.py` | AES-GCM encryption/decryption and RSA key wrapping |
| `src/privacy_guard/crypto/image_password.py` | Per-image password derivation and authenticated payload encryption |
| `src/privacy_guard/crypto/format.py` | Existing encrypted-container constants |
| `src/privacy_guard/imaging/operations.py` | Image orientation, normalization and region validation |
| `src/privacy_guard/pipeline.py` | Crop, protect, mask and restore document regions |
| `src/privacy_guard/image_store.py` | Assign image IDs, locate and delete selected protected folders without a database |
| `src/privacy_guard/isolation.py` | Start one process per protection and warn about common synced locations |
| `src/privacy_guard/protection_worker.py` | Internal process that detects, protects and removes a selected source |
| `gui.py` | Local window for protecting, previewing, listing and restoring images |
| `src/privacy_guard/benchmark.py` | Encryption timing, storage and pixel-correctness metrics |
| `src/privacy_guard/file_io.py` | Bounded reads and output writes without overwriting |
| `tests/` | Encryption, imaging, labels, metrics and CLI regression tests |
| `pyproject.toml` | Package metadata, dependencies and installed command |

Imports are explicit package imports, for example:

```python
from privacy_guard.crypto.hybrid import encrypt_bytes, decrypt_bytes
from privacy_guard.detection.model import load_document_model
from privacy_guard.pipeline import protect_image, restore
```

There are no wildcard imports or path modifications. The CLI owns password prompts;
library functions receive password bytes as arguments.

## Dataset and model

The repository includes the combined `dataset/` beside `pyproject.toml`.
You may also supply an absolute path to another dataset. It must contain `data.yaml`,
`train/images`, `train/labels`, `valid/images`, `valid/labels`, and optionally
`test/images` and `test/labels`.

Class IDs are fixed:

| ID | Class |
| --- | --- |
| 0 | `aadhaar_card` |
| 1 | `pan_card` |
| 2 | `payment_card` |

```powershell
python -m privacy_guard check --dataset dataset
python -m privacy_guard train --dataset dataset --epochs 50 --device cpu
python -m privacy_guard evaluate --dataset dataset --weights runs/train-2/weights/best.pt --split test
python -m privacy_guard predict --source sample.jpg --weights runs/train-2/weights/best.pt
```

Training starts from `yolov8n.pt` by default; its initial download needs internet.
Use `--model path/to/yolov8n.pt` for a local base checkpoint. Use the actual
training output directory printed by the command if it differs from `runs/train`.
The earlier single-class credit-card checkpoint is rejected.
Evaluation writes overall/per-class metrics JSON. Use `--split val` if no test split exists.

## Selective protection and restoration

For several images, keep using the same key pair and let the small organizer
assign a random ID to each protected folder. You can use your **existing**
`keys/public.pem` and `keys/private.pem`; only run `keygen` if you do not have
a key pair already. The store folder is created by the first `image-add`.

```powershell
$entry = python -m privacy_guard image-add --store protected_images --input sample.jpg --weights runs/train-2/weights/best.pt --public-key keys/public.pem --name "Demo document" | ConvertFrom-Json
python -m privacy_guard image-list --store protected_images
python -m privacy_guard image-restore --store protected_images --id $entry.id --private-key keys/private.pem --output restored.png
```

The image folder is `protected_images/<ID>/` and contains `protected.png`,
`regions.islenc`, `forensic_report.json` and a short `image.json` label.
`image.json` stores the random ID, label and timestamp, not the input path or
private key. Choose a label that does not disclose private information. The
private key and both passwords remain outside the store. A fresh AES key and nonce
are still generated for each image, even when reusing the RSA key pair.
The GUI's Delete button and terminal menu option 5 remove only the selected
folder after confirmation. They do not remove the key pair or guarantee secure
erasure of previously deleted data or external copies.
The CLI reports cleanup status on stderr, leaving the JSON from `image-add`
on stdout for the PowerShell example above. It warns on stderr for recognized
synced folders. The desktop window asks you to confirm when it recognizes one.

Each `image-add` prompts twice for a new image password. `image-restore` asks
for that image password and your private-key password. Previously protected
bundles that have an authenticated image ID and no image-password layer can
still restore: press Enter at the image-password prompt. An image-password
protected bundle requires its password; a blank value cannot bypass it.

New image-store bundles include their ID **inside the encrypted AES-GCM payload**.
Restoring by ID compares this authenticated ID to the selected folder before
writing an image. Copying a valid preview and sidecar from one ID folder to
another is rejected. The readable `image.json` label remains editable and
untrusted. This is not a digital signature, a user permission system, or
protection against deletion/rollback. Anyone with the public key can create
new ciphertext; this check only binds an existing bundle to its stored ID.
The manager has no SQLite, AWS or TPM dependency.

The organizer restores images created with an authenticated ID. A bundle with
no matching ID is rejected before a restored image is written.
Keep the private key outside `protected_images`, use a long unpredictable
passphrase, and back up the encrypted private key separately: copying both
the key and sidecar permits offline passphrase guesses.

Either `protect` or `image-add` can use `--fill texture` or `--fill inpaint`;
the default remains `--fill black`. The menu offers the same three choices.

Generate keys once. Reuse your existing keys if you already have them.

```powershell
python -m privacy_guard keygen --directory keys
python -m privacy_guard protect --input sample.jpg --weights runs/train-2/weights/best.pt --public-key keys/public.pem --output protected_sample
python -m privacy_guard restore --image protected_sample/protected.png --regions protected_sample/regions.islenc --private-key keys/private.pem --output restored.png
```

Passwords are entered interactively. Each protection asks for a new image
password and confirmation; each restoration asks for it again and separately
asks for the private-key password. Output paths must be new and their parent
directories must exist. Restoration requires PNG to preserve exact pixels.

The protected PNG contains black document rectangles and the remaining visible
pixels. The sidecar encrypts original region pixels, coordinates and integrity
metadata. Overlapping boxes are supported. No detections means protection stops
without creating output. Detection misses can leave private information visible.

Encryption uses a fresh 32-byte AES key and 12-byte nonce per outer payload.
RSA-OAEP-SHA256 wraps that AES key. The image password is converted to a separate
32-byte key using scrypt and a fresh 16-byte salt, then the region payload is
encrypted with its own AES-256-GCM nonce. The outer AES-256-GCM layer encrypts
this password-protected payload. SHA-256 also binds the exact preview PNG and
restored normalized pixels. The `ISLENC01` outer container, `ISL-ROI-1` region
format, and existing PEM keys remain usable.

Restoration reproduces normalized, orientation-corrected RGB/RGBA pixels.
The original selected image is removed after successful protection. Restoration
checks the SHA-256 hash stored inside the authenticated encrypted payload.
It does not reconstruct the original JPEG bytes or its metadata. PNG/JPEG
encoding differences affect reported storage overhead. Benchmark timing includes
key loading/unlocking but excludes password entry, YOLO, cropping, masking and
image output. It is a single-image measurement.

Whole-file encryption remains available:

```powershell
python -m privacy_guard encrypt --input sample.jpg --output sample.islenc --public-key keys/public.pem
python -m privacy_guard decrypt --input sample.islenc --output recovered.jpg --private-key keys/private.pem
```

## Migration from loose scripts

| Previous command prefix | New command prefix |
| --- | --- |
| `python detector.py` | `python -m privacy_guard` |
| `python encryption.py` | `python -m privacy_guard` |
| `python selective.py` | `python -m privacy_guard` |
| `python benchmark_encryption.py` | `python -m privacy_guard benchmark` |

Existing arguments remain the same. Paths resolve relative to your terminal's
working directory. The installed package can run from any folder, using absolute
paths when needed. This repository includes the combined dataset and the trained
`runs/train-2/weights/best.pt` checkpoint. `sample.jpg` in the examples is a
user-supplied test photo; place it outside `dataset/` before protection. Do not
commit private keys, saved bundles or private images.

## Testing

```powershell
python -m unittest discover -s tests -v
```

Tests cover authentication failures, wrong keys/passwords, overwrite prevention,
overlapping regions, RGBA, image orientation, outside-region preservation,
three-class labels, per-class metrics and installed CLI operation.
The detector adapter test uses a fake model; it does not establish detection
accuracy. See `VALIDATION.txt` for this refactor's verification results.

## SHA-256 integrity comparison (version 1.1)

For a controlled lab test with a separate synthetic reference image, compare
its pixels with a restored image:

```powershell
python -m privacy_guard verify --original reference.jpg --restored restored.png --report integrity_report.json
```

This prints both SHA-256 digests and a PASS/FAIL result. The default pixel mode
hashes normalized image mode, dimensions and pixel bytes after orientation
correction. This allows an original JPEG and restored PNG to match when their
decoded pixels are identical. It excludes compression and file metadata.
A changed pixel, image mode or dimensions produces a mismatch.

For whole-file encryption/decryption, use exact file-byte comparison:

```powershell
python -m privacy_guard verify --original reference.jpg --restored recovered.jpg --mode file
```

The command returns exit code 0 for a match and 1 for a mismatch/error.
The optional report must be a new file. No originals or restored files are modified.
The new module is `src/privacy_guard/integrity.py`.

Restoration already checks the SHA-256 hash stored inside the authenticated
encrypted payload. This optional command compares against a separate trusted test reference and
can produce a JSON record for evaluation. It does not replace
AES-GCM authentication. Treat your original as the trusted comparison reference;
the exported JSON report itself is not signed or authenticated.

The comparison command uses a versioned image-hash format that includes dimensions
and mode. Its digest therefore differs from the existing internal pixels-only
hash even for the same image; each pair is compared using its own format.
Existing encrypted files and the restore format remain unchanged.

## File forensics (version 1.2)

Inspect an input without running YOLO:

```powershell
python -m privacy_guard inspect --input sample.jpg --report inspection.json
```

Inspection checks the file signature against its extension and the image decoder's
format, checks dimensions and frame count, verifies structure, fully decodes the
image, and computes SHA-256 on the exact input bytes. Supported formats are JPEG,
PNG, WebP, BMP and TIFF. Inputs are limited to 64 MiB, 12 million pixels and one
frame. Extension mismatches are rejected: an actual PNG named .jpg must be given
the correct extension. Metadata reporting contains presence flags only, never
GPS coordinates, camera names, arbitrary metadata keys, or metadata values.
Metadata flags depend on what the image decoder exposes; this is not a complete
binary-forensics scanner or a malware scanner.

Protection now performs this inspection automatically before loading YOLO.
Inspection and detection use the same bounded in-memory snapshot, so an input
file changed after reading cannot silently change the pixels being processed.
After masking, the pipeline decodes its generated PNG and confirms:

- Image dimensions and colour mode are preserved.
- Every channel outside the union of the bounding boxes is unchanged.
- No decoder-visible metadata remains in the protected PNG.

A failed check stops output creation. Successful protection creates:

| File | Contents |
| --- | --- |
| protected.png | Masked image |
| regions.islenc | Encrypted crops, coordinates, integrity hashes and authenticated forensic record |
| forensic_report.json | Readable copy of the inspection and protection checks |

The readable report contains hashes, image properties, a local-clock UTC inspection
timestamp, and metadata-presence flags. Treat it as potentially sensitive evidence.
It is **not signed or authenticated**. The authoritative recorded copy is inside
the AES-GCM encrypted sidecar; changing the readable report does not affect restore.

Request an optional report while restoring:

```powershell
python -m privacy_guard restore --image protected_sample/protected.png --regions protected_sample/regions.islenc --private-key keys/private.pem --output restored.png --report restoration_report.json
```

This report is emitted only after successful authentication, preview hash checking,
restored-pixel hash checking and outside-region verification. It includes the
forensic record recovered from the encrypted payload. It is also an unsigned
export. Existing files without forensic records still restore; their report says
`legacy_not_recorded`. The encrypted file format remains ISLENC01 / ISL-ROI-1.

Library callers supplying an already-decoded image to `protect_image` without an
inspection record receive protection checks, but the report explicitly says that
source-file inspection was unavailable. Normal CLI protection always inspects the
input file.

Use the original `verify` command for an independent original/restored comparison.
Forensics does not establish who created an image, prove it was never edited, prevent
deletion or replay of older valid bundles, or provide a trusted timestamp. There is
no persistent attempt history or signed audit log in this version. Invalid inspection
exits with an error and does not produce a success report.

This update adds file forensics; restored PNGs are still written to the requested
output path. It does not implement a RAM-only image viewer or batch processing.
