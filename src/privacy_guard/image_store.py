"""Tiny ID-based organizer for single-image protected bundles.

The folder name is a lookup ID, not an authentication or access-control layer.
AES-GCM and the authenticated image payload are checked by pipeline.restore.
"""
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from uuid import uuid4

from privacy_guard.file_io import read_bounded, write_new
from privacy_guard.pipeline import protect_with_yolo, remove_original_after_protection, restore


ID = re.compile(r'img-[0-9a-f]{32}\Z')


class ImageStore:
    def __init__(self, folder, *, create=False):
        self.root = Path(folder).expanduser().resolve()
        if create:
            self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not self.root.is_dir():
            raise ValueError('Image store must be a directory.')

    def _bundle(self, image_id):
        if not isinstance(image_id, str) or not ID.fullmatch(image_id):
            raise ValueError('Invalid image ID.')
        bundle = self.root / image_id
        if bundle.is_symlink():
            raise ValueError('Linked image folders are not allowed.')
        for name in ('protected.png', 'regions.islenc', 'image.json'):
            if (bundle / name).is_symlink():
                raise ValueError('Linked bundle files are not allowed.')
        return bundle

    def add(self, source, weights, public_key, name='Image', conf=0.25,
            device='cpu', imgsz=640, *, image_password, fill='black'):
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 120 or any(ord(c) < 32 for c in name):
            raise ValueError('Name must be 1–120 characters without control characters.')
        image_id = 'img-' + uuid4().hex
        bundle = self._bundle(image_id)
        record = {'id': image_id, 'name': name.strip(),
                  'created_utc': datetime.now(timezone.utc).isoformat()}
        protect_with_yolo(source, weights, public_key, bundle, conf, device, imgsz,
                          image_password=image_password, fill=fill, image_id=image_id,
                          defer_source_removal=True)
        try:
            write_new(bundle / 'image.json',
                      (json.dumps(record, separators=(',', ':')) + '\n').encode('utf-8'))
        except BaseException:
            for filename in ('protected.png', 'regions.islenc', 'forensic_report.json'):
                (bundle / filename).unlink(missing_ok=True)
            bundle.rmdir()
            raise
        try:
            remove_original_after_protection(source, bundle)
        except (OSError, ValueError) as exc:
            raise RuntimeError(f'Protected bundle saved at {bundle}, but the selected '
                               f'original was retained: {exc}') from exc
        return record

    def _record(self, bundle):
        record = json.loads(read_bounded(bundle / 'image.json', 4096))
        if not isinstance(record, dict) or record.get('id') != bundle.name:
            raise ValueError('Invalid image record.')
        return {key: record[key] for key in ('id', 'name', 'created_utc')}

    def list(self):
        results = []
        for bundle in self.root.iterdir():
            if ID.fullmatch(bundle.name) and bundle.is_dir():
                safe = self._bundle(bundle.name)
                if (safe / 'image.json').is_file():
                    results.append(self._record(safe))
        return sorted(results, key=lambda r: (r['created_utc'], r['id']))

    def delete(self, image_id):
        """Remove only the selected bundle; refuse unexpected contents."""
        bundle = self._bundle(image_id)
        record = self._record(bundle)
        allowed = {'protected.png', 'regions.islenc', 'image.json', 'forensic_report.json'}
        for entry in bundle.iterdir():
            if entry.name not in allowed or not entry.is_file() or entry.is_symlink():
                raise ValueError('Saved image has unexpected contents; delete it manually after inspection.')
        for filename in ('protected.png', 'regions.islenc', 'forensic_report.json', 'image.json'):
            (bundle / filename).unlink(missing_ok=True)
        bundle.rmdir()
        return record

    def restore(self, image_id, destination, private_key, password, *, image_password):
        bundle = self._bundle(image_id)
        self._record(bundle)
        output = Path(destination).expanduser().resolve()
        if output == self.root or self.root in output.parents:
            raise ValueError('Restored images must be saved outside the encrypted image store.')
        return restore(bundle / 'protected.png', bundle / 'regions.islenc', output,
                       private_key, password, expected_image_id=image_id,
                       image_password=image_password)
