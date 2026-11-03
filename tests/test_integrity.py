import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from PIL import Image
from privacy_guard.cli import main
from privacy_guard.integrity import compare_integrity


class IntegrityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.original = self.root / 'input.jpg'
        self.restored = self.root / 'restored.png'
        Image.new('RGB', (8, 8), (100, 50, 20)).save(self.original)
        with Image.open(self.original) as image:
            image.convert('RGB').save(self.restored)

    def test_jpeg_png_pixels_match_while_file_bytes_differ(self):
        self.assertTrue(compare_integrity(self.original, self.restored)['match'])
        self.assertFalse(compare_integrity(self.original, self.restored, 'file')['match'])

    def test_one_pixel_change_fails(self):
        with Image.open(self.restored) as loaded:
            changed = loaded.copy()
        changed.putpixel((0, 0), (0, 0, 0))
        changed.save(self.restored)
        self.assertFalse(compare_integrity(self.original, self.restored)['match'])

    def test_exact_file_match(self):
        copied = self.root / 'copy.jpg'
        copied.write_bytes(self.original.read_bytes())
        self.assertTrue(compare_integrity(self.original, copied, 'file')['match'])

    def test_dimensions_are_bound_to_hash(self):
        a, b = self.root / 'a.png', self.root / 'b.png'
        Image.new('RGB', (4, 8), 'black').save(a)
        Image.new('RGB', (8, 4), 'black').save(b)
        self.assertFalse(compare_integrity(a, b)['match'])

    def test_cli_report_and_failure_exit(self):
        report = self.root / 'integrity.json'
        args = ['verify', '--original', str(self.original), '--restored', str(self.restored)]
        with contextlib.redirect_stdout(io.StringIO()):
            main(args + ['--report', str(report)])
            with self.assertRaises(SystemExit) as caught:
                main(args + ['--mode', 'file'])
        self.assertEqual(caught.exception.code, 1)
        self.assertTrue(json.loads(report.read_text())['match'])
