import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
from PIL import Image
import encryption as enc
import selective as roi


class SelectiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        cls.password = b'test-password'
        cls.keys = enc.generate_keys(cls.root / 'keys', cls.password)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.case = tempfile.TemporaryDirectory(dir=self.root)
        self.addCleanup(self.case.cleanup)
        self.folder = Path(self.case.name)
        self.image = Image.frombytes('RGB', (16, 12), bytes(i % 251 for i in range(576)))
        self.boxes = [[1, 2, 7, 8], [5, 5, 11, 10]]
        self.bundle = self.folder / 'protected'
        self.restored = self.folder / 'restored.png'

    def protect(self):
        roi.protect_image(self.image, self.boxes, self.bundle, self.keys / 'public.pem')

    def restore(self):
        roi.restore(self.bundle / 'protected.png', self.bundle / 'regions.islenc',
                    self.restored, self.keys / 'private.pem', self.password)

    def test_overlaps_and_unchanged_outside_pixels(self):
        self.protect()
        with Image.open(self.bundle / 'protected.png') as preview:
            for y in range(12):
                for x in range(16):
                    covered = any(a <= x < c and b <= y < d for a,b,c,d in self.boxes)
                    self.assertEqual(preview.getpixel((x,y)), (0,0,0) if covered else self.image.getpixel((x,y)))
        self.restore()
        with Image.open(self.restored) as result:
            self.assertEqual(result.tobytes(), self.image.tobytes())

    def test_rgba_restoration(self):
        self.image = self.image.convert('RGBA')
        self.image.putalpha(77)
        self.protect()
        with Image.open(self.bundle / 'protected.png') as preview:
            self.assertEqual(preview.getpixel((2,3)), (0,0,0,255))
        self.restore()
        with Image.open(self.restored) as result:
            self.assertEqual(result.tobytes(), self.image.tobytes())

    def test_no_detections_and_invalid_boxes(self):
        for boxes in [[], [[0,0,17,12]], [[4,4,4,6]], [[0.1,0,2,2]]]:
            with self.assertRaises(ValueError):
                roi.protect_image(self.image, boxes, self.bundle, self.keys / 'public.pem')
            self.assertFalse(self.bundle.exists())

    def test_tampered_preview(self):
        self.protect()
        path = self.bundle / 'protected.png'
        path.write_bytes(path.read_bytes() + b'changed')
        with self.assertRaises(ValueError):
            self.restore()
        self.assertFalse(self.restored.exists())

    def test_tampered_sidecar(self):
        self.protect()
        path = self.bundle / 'regions.islenc'
        contents = bytearray(path.read_bytes())
        contents[-1] ^= 1
        path.write_bytes(contents)
        with self.assertRaises(ValueError):
            self.restore()
        self.assertFalse(self.restored.exists())

    def test_no_overwrite(self):
        self.protect()
        with self.assertRaises(FileExistsError):
            self.protect()
        self.restored.write_bytes(b'keep')
        with self.assertRaises(FileExistsError):
            self.restore()
        self.assertEqual(self.restored.read_bytes(), b'keep')

    def test_orientation_and_metadata_removal(self):
        image = self.image.copy()
        exif = Image.Exif()
        exif[274] = 6
        source = self.folder / 'rotated.png'
        image.save(source, exif=exif)
        normalized = roi.load_image(source)
        self.assertEqual(normalized.size, (12,16))
        self.assertFalse(normalized.info)

    def test_yolo_adapter_without_model_runtime(self):
        source = self.folder / 'input.png'
        self.image.save(source)
        class FakeResult:
            orig_shape = (12,16)
        class FakeModel:
            def predict(model_self, **kwargs):
                self.assertEqual(kwargs['source'].tobytes(), self.image.tobytes())
                self.assertFalse(kwargs['save'])
                return [FakeResult()]
        with patch('detector.require_card_model', return_value=FakeModel()), patch(
                'detector.box_records', return_value=[{'xyxy': b} for b in self.boxes]):
            roi.protect_with_yolo(source, 'dummy.pt', self.keys / 'public.pem', self.bundle)
        self.restore()
        with Image.open(self.restored) as result:
            self.assertEqual(result.tobytes(), self.image.tobytes())


if __name__ == '__main__':
    unittest.main()
