"""Launch one short-lived process for each image protection operation."""
import ctypes
import json
import os
from pathlib import Path
import subprocess
import sys


SYNCED_NAMES = {'dropbox', 'google drive', 'icloud drive', 'box', 'onedrive'}


def windows_is_elevated():
    """Check the Windows token before handling an original document image."""
    if sys.platform != 'win32':
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError) as exc:
        raise RuntimeError('Could not check Windows administrator privileges.') from exc


def synced_folder_warning(source, environ=None):
    """Recognize common sync locations; absence of a warning is not a safety check."""
    source = Path(source).expanduser().resolve()
    environment = os.environ if environ is None else environ
    for key in ('OneDrive', 'OneDriveConsumer', 'OneDriveCommercial'):
        root = environment.get(key)
        if root and source.is_relative_to(Path(root).expanduser().resolve()):
            return 'This image is in a synced folder. Its cloud copy or version history may remain after local deletion.'
    if any(part.casefold() in SYNCED_NAMES or part.casefold().startswith('onedrive - ')
           for part in source.parent.parts):
        return 'This image appears to be in a synced folder. Its cloud copy or version history may remain after local deletion.'
    return None


def _run_worker(request):
    if windows_is_elevated():
        raise ValueError('Run VS Code or this command as a standard Windows user, '
                         'not as administrator, before protecting an image.')
    # Password travels through a private stdin pipe, never through command-line arguments.
    encoded = json.dumps(request).encode('utf-8')
    if len(encoded) > 64_000:
        raise ValueError('Protection request is too large.')
    completed = subprocess.run([sys.executable, '-m', 'privacy_guard.protection_worker'],
                               input=encoded, capture_output=True, check=False)
    if len(completed.stdout) > 16_000:
        raise RuntimeError('Image worker returned an oversized response.')
    try:
        response = json.loads(completed.stdout)
    except (ValueError, UnicodeDecodeError) as exc:
        raise RuntimeError('Image worker ended without a valid response.') from exc
    if not isinstance(response, dict) or not isinstance(response.get('ok'), bool):
        raise RuntimeError('Image worker returned an invalid response.')
    if completed.returncode != 0 or not response['ok']:
        raise ValueError(str(response.get('error', 'Image worker failed.')))
    if response.get('selected_source_absent') is not True:
        raise RuntimeError('Image worker did not confirm removal of the selected source.')
    return response


def add_image_isolated(source, weights, public_key, store, *, name='Image', fill='black',
                       image_password, conf=0.25, device='cpu', imgsz=640):
    response = _run_worker({'action': 'image-add', 'source': str(source), 'weights': str(weights),
                            'public_key': str(public_key), 'store': str(store), 'name': name,
                            'fill': fill, 'image_password': image_password.decode('utf-8'),
                            'conf': conf, 'device': device, 'imgsz': imgsz})
    record = response.get('record')
    if not isinstance(record, dict) or not isinstance(record.get('id'), str):
        raise RuntimeError('Image worker did not return an image ID.')
    return record


def protect_image_isolated(source, weights, public_key, output, *, fill='black',
                           image_password, conf=0.25, device='cpu', imgsz=640):
    _run_worker({'action': 'protect', 'source': str(source), 'weights': str(weights),
                 'public_key': str(public_key), 'output': str(output), 'fill': fill,
                 'image_password': image_password.decode('utf-8'), 'conf': conf,
                 'device': device, 'imgsz': imgsz})
    return Path(output)
