import contextlib
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from privacy_guard.cli import main

COMMANDS = ['check', 'train', 'evaluate', 'predict', 'keygen', 'encrypt',
            'decrypt', 'protect', 'restore', 'benchmark', 'verify', 'inspect',
            'image-add', 'image-list', 'image-restore']


class CliTests(unittest.TestCase):
    def test_all_commands_work_from_outside_project(self):
        with tempfile.TemporaryDirectory() as folder:
            for command in COMMANDS:
                with self.subTest(command=command):
                    result = subprocess.run(
                        [sys.executable, '-m', 'privacy_guard', command, '--help'],
                        cwd=folder, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn('usage:', result.stdout)

    def test_cli_keygen_encrypt_decrypt_round_trip(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / 'source.bin'
            original = b'private document test\x00\xff'
            source.write_bytes(original)
            encrypted, restored = root / 'data.islenc', root / 'restored.bin'
            with patch('privacy_guard.cli.prompt_password', return_value=b'test-password'), contextlib.redirect_stdout(io.StringIO()):
                main(['keygen', '--directory', str(root / 'keys')])
                main(['encrypt', '--input', str(source), '--output', str(encrypted),
                      '--public-key', str(root / 'keys/public.pem')])
                main(['decrypt', '--input', str(encrypted), '--output', str(restored),
                      '--private-key', str(root / 'keys/private.pem')])
            self.assertFalse(source.exists())
            self.assertEqual(original, restored.read_bytes())

    def test_crypto_import_does_not_load_yolo(self):
        result = subprocess.run([sys.executable, '-c',
            'import sys; import privacy_guard.crypto.hybrid; assert "ultralytics" not in sys.modules'],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
