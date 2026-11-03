import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from PIL import Image

from privacy_guard.crypto.keys import generate_keys
from privacy_guard.image_store import ImageStore
from privacy_guard.isolation import (add_image_isolated, protect_image_isolated,
                                     synced_folder_warning)


class IsolationTests(unittest.TestCase):
    def test_sync_warning_recognizes_environment_and_common_folders(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cloud = root / 'Cloud Images'
            image = cloud / 'sample.jpg'
            self.assertIsNotNone(synced_folder_warning(image, {'OneDrive': str(cloud)}))
            self.assertIsNotNone(synced_folder_warning(root/'OneDrive - University'/'sample.jpg', {}))
            self.assertIsNone(synced_folder_warning(root/'Private'/'sample.jpg', {}))

    def test_password_is_passed_through_stdin_not_argv(self):
        password = b'unique-image-password'
        response = {'ok': True, 'selected_source_absent': True,
                    'record': {'id': 'img-' + 'a'*32, 'name': 'Demo'}}
        completed = subprocess.CompletedProcess([], 0, json.dumps(response).encode(), b'')
        with patch('privacy_guard.isolation.subprocess.run', return_value=completed) as launch:
            record = add_image_isolated('input.jpg', 'model.pt', 'key.pem', 'store',
                                        image_password=password)
        self.assertEqual(record['id'], response['record']['id'])
        self.assertNotIn('unique-image-password', ' '.join(launch.call_args.args[0]))
        self.assertIn(password, launch.call_args.kwargs['input'])
        self.assertEqual(launch.call_args.kwargs['capture_output'], True)

    def test_failure_does_not_claim_source_cleanup(self):
        completed = subprocess.CompletedProcess([], 1,
                     b'{"ok":false,"error":"No detected documents"}', b'')
        with patch('privacy_guard.isolation.subprocess.run', return_value=completed):
            with self.assertRaisesRegex(ValueError, 'No detected documents'):
                protect_image_isolated('input.jpg', 'model.pt', 'key.pem', 'output',
                                       image_password=b'unique-image-password')

    def test_elevated_windows_session_is_rejected_before_starting_worker(self):
        with patch('privacy_guard.isolation.windows_is_elevated', return_value=True), \
             patch('privacy_guard.isolation.subprocess.run') as launch:
            with self.assertRaisesRegex(ValueError, 'standard Windows user'):
                protect_image_isolated('input.jpg', 'model.pt', 'key.pem', 'output',
                                       image_password=b'unique-image-password')
            launch.assert_not_called()

    def test_real_worker_rejects_bad_source_and_keeps_it(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'invalid.jpg'
            source.write_bytes(b'not an image')
            output = Path(directory) / 'protected'
            with self.assertRaises(ValueError):
                protect_image_isolated(source, 'fake.pt', 'fake.pem', output,
                                       image_password=b'unique-image-password')
            self.assertTrue(source.exists())
            self.assertFalse(output.exists())

    def test_real_worker_protects_removes_and_restores_with_simulated_detector(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stub = root/'stubs'
            stub.mkdir()
            (stub/'ultralytics.py').write_text('''
from types import SimpleNamespace
class YOLO:
    names = {0: 'aadhaar_card', 1: 'pan_card', 2: 'payment_card'}
    task = 'detect'
    def __init__(self, weights): pass
    def predict(self, source, **kwargs):
        box = SimpleNamespace(xyxy=[SimpleNamespace(tolist=lambda: [1, 1, 6, 6])],
                              cls=SimpleNamespace(item=lambda: 0),
                              conf=SimpleNamespace(item=lambda: 0.99))
        return [SimpleNamespace(orig_shape=(source.height, source.width),
                                boxes=[box], names=self.names)]
''')
            keys = generate_keys(root/'keys', b'private-key-password')
            weights = root/'best.pt'
            weights.touch()
            source = root/'test.png'
            original = Image.new('RGB', (10, 10), (12, 45, 92))
            original.save(source)
            project_src = Path(__file__).resolve().parents[1]/'src'
            pythonpath = os.pathsep.join([str(stub), str(project_src),
                                           os.environ.get('PYTHONPATH', '')])
            with patch.dict(os.environ, {'PYTHONPATH': pythonpath}):
                record = add_image_isolated(source, weights, keys/'public.pem', root/'store',
                                            image_password=b'unique-image-password', fill='texture')
            self.assertFalse(source.exists())
            bundle = root/'store'/record['id']
            self.assertTrue((bundle/'protected.png').is_file())
            self.assertTrue((bundle/'regions.islenc').is_file())
            with Image.open(bundle/'protected.png') as preview:
                self.assertNotEqual(preview.getpixel((3, 3)), (0, 0, 0))
            restored = root/'restored.png'
            ImageStore(root/'store').restore(record['id'], restored, keys/'private.pem',
                                             b'private-key-password',
                                             image_password=b'unique-image-password')
            with Image.open(restored) as output:
                self.assertEqual(output.tobytes(), original.tobytes())
