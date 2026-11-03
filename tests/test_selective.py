from privacy_guard.crypto.keys import generate_keys
from privacy_guard.pipeline import protect_image, protect_with_yolo, remove_original_after_protection, restore
from privacy_guard.imaging.operations import load_image
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import sys
import numpy as np
from PIL import Image


class SelectiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        cls.password = b'test-password'
        cls.image_password = b'unique-image-password'
        cls.keys = generate_keys(cls.root / 'keys', cls.password)

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
        protect_image(self.image, self.boxes, self.bundle, self.keys / 'public.pem',
                      image_password=self.image_password)

    def restore(self):
        restore(self.bundle / 'protected.png', self.bundle / 'regions.islenc',
                    self.restored, self.keys / 'private.pem', self.password,
                    image_password=self.image_password)

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

    def test_inpaint_receives_blacked_pixels_and_preserves_outside(self):
        self.image = self.image.convert('RGBA')
        self.image.putalpha(77)
        called = []
        def simulated_inpaint(pixels, mask, radius, algorithm):
            called.append(True)
            self.assertEqual(mask.dtype, np.uint8)
            self.assertTrue(np.all(pixels[mask == 255] == 0))
            self.assertEqual(radius, 3)
            self.assertEqual(algorithm, 1)
            fake_result = np.full_like(pixels, 255)  # Even if outside is modified.
            fake_result[mask == 255] = [37, 99, 150]
            return fake_result
        fake_cv2 = SimpleNamespace(INPAINT_TELEA=1, inpaint=simulated_inpaint)
        with patch.dict(sys.modules, {'cv2': fake_cv2}):
            protect_image(self.image, self.boxes, self.bundle, self.keys / 'public.pem',
                          fill='inpaint', image_password=self.image_password)
        self.assertEqual(called, [True])
        with Image.open(self.bundle / 'protected.png') as preview:
            self.assertEqual(preview.getpixel((2, 3)), (37, 99, 150, 255))
            self.assertEqual(preview.getpixel((0, 0)), self.image.getpixel((0, 0)))
        self.restore()
        with Image.open(self.restored) as result:
            self.assertEqual(result.tobytes(), self.image.tobytes())

    def test_texture_fill_uses_clean_pixels_and_restores_original(self):
        image = Image.new('RGB', (80, 48), (91, 150, 128))
        for y in range(image.height):
            for x in range(image.width):
                image.putpixel((x, y), (91 + x % 7, 150 + y % 5, 128 + x % 3))
        box = [27, 12, 54, 36]
        for y in range(box[1], box[3]):
            for x in range(box[0], box[2]):
                image.putpixel((x, y), (250, 10, 5))
        protect_image(image, [box], self.bundle, self.keys / 'public.pem',
                      fill='texture', image_password=self.image_password)
        with Image.open(self.bundle / 'protected.png') as preview:
            self.assertNotEqual(preview.getpixel((38, 25)), (250, 10, 5))
            self.assertNotEqual(preview.getpixel((38, 25)), (0, 0, 0))
            for y in range(image.height):
                for x in range(image.width):
                    if not (box[0] <= x < box[2] and box[1] <= y < box[3]):
                        self.assertEqual(preview.getpixel((x, y)), image.getpixel((x, y)))
        restore(self.bundle / 'protected.png', self.bundle / 'regions.islenc',
                self.restored, self.keys / 'private.pem', self.password,
                image_password=self.image_password)
        with Image.open(self.restored) as output:
            self.assertEqual(output.tobytes(), image.tobytes())

    def test_texture_fill_no_clean_patch_falls_back_without_leaking(self):
        image = Image.new('RGB', (12, 12), (200, 30, 20))
        protect_image(image, [[0, 0, 12, 12]], self.bundle, self.keys / 'public.pem',
                      fill='texture', image_password=self.image_password)
        with Image.open(self.bundle / 'protected.png') as preview:
            self.assertEqual(preview.getpixel((5, 5)), (0, 0, 0))
        restore(self.bundle / 'protected.png', self.bundle / 'regions.islenc',
                self.restored, self.keys / 'private.pem', self.password,
                image_password=self.image_password)
        with Image.open(self.restored) as output:
            self.assertEqual(output.tobytes(), image.tobytes())

    def test_no_detections_and_invalid_boxes(self):
        for boxes in [[], [[0,0,17,12]], [[4,4,4,6]], [[0.1,0,2,2]]]:
            with self.assertRaises(ValueError):
                protect_image(self.image, boxes, self.bundle, self.keys / 'public.pem',
                              image_password=self.image_password)
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
        normalized = load_image(source)
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
        with patch('privacy_guard.pipeline.load_document_model', return_value=FakeModel()), patch(
                'privacy_guard.pipeline.box_records', return_value=[{'xyxy': b} for b in self.boxes]):
            protect_with_yolo(source, 'dummy.pt', self.keys / 'public.pem', self.bundle,
                              image_password=self.image_password)
        self.assertFalse(source.exists())
        self.restore()
        with Image.open(self.restored) as result:
            self.assertEqual(result.tobytes(), self.image.tobytes())

    def test_changed_source_is_kept(self):
        source = self.folder / 'input.png'
        self.image.save(source)
        class FakeModel:
            def predict(model_self, **kwargs):
                return [SimpleNamespace(orig_shape=(12, 16))]
        with patch('privacy_guard.pipeline.load_document_model', return_value=FakeModel()), \
             patch('privacy_guard.pipeline.box_records', return_value=[{'xyxy': self.boxes[0]}]):
            protect_with_yolo(source, 'dummy.pt', self.keys / 'public.pem', self.bundle,
                              defer_source_removal=True, image_password=self.image_password)
        source.write_bytes(source.read_bytes() + b'changed')
        with self.assertRaisesRegex(ValueError, 'original was kept'):
            remove_original_after_protection(source, self.bundle)
        self.assertTrue(source.exists())


if __name__ == '__main__':
    unittest.main()
