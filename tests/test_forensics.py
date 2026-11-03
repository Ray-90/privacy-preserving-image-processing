import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from PIL import Image, PngImagePlugin
from privacy_guard.crypto.hybrid import decrypt_bytes, encrypt_bytes
from privacy_guard.crypto.keys import generate_keys
from privacy_guard.forensics import inspect_image, verify_protected_image
from privacy_guard.imaging.operations import png_bytes
from privacy_guard.pipeline import protect_image, protect_with_yolo, restore
from privacy_guard.crypto.image_password import protect_payload, unlock_payload


class ForensicsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workspace = tempfile.TemporaryDirectory()
        cls.root = Path(cls.workspace.name)
        cls.password = b'forensics-test'
        cls.keys = generate_keys(cls.root / 'keys', cls.password)

    @classmethod
    def tearDownClass(cls):
        cls.workspace.cleanup()

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(dir=self.root)
        self.addCleanup(tmp.cleanup)
        self.folder = Path(tmp.name)
        self.path = self.folder / 'source.png'
        self.image = Image.new('RGB', (12, 10), (100, 50, 25))
        self.image.save(self.path)

    def test_metadata_presence_without_values(self):
        metadata = PngImagePlugin.PngInfo()
        metadata.add_text('secret-custom-key', 'private-location-value')
        exif = Image.Exif()
        exif[271] = 'private-camera-value'
        self.image.save(self.path, pnginfo=metadata, exif=exif)
        image, record = inspect_image(self.path)
        self.assertTrue(record['metadata_presence']['text_or_comment_present'])
        self.assertTrue(record['metadata_presence']['exif_present'])
        encoded = json.dumps(record)
        for value in ['private-camera-value', 'private-location-value', 'secret-custom-key']:
            self.assertNotIn(value, encoded)
        self.assertFalse(image.info)

    def test_renamed_and_corrupt_inputs_rejected(self):
        renamed = self.folder / 'renamed.jpg'
        renamed.write_bytes(self.path.read_bytes())
        with self.assertRaisesRegex(ValueError, 'extension'):
            inspect_image(renamed)
        self.path.write_bytes(b'\x89PNG\r\n\x1a\ninvalid')
        with self.assertRaises((ValueError, OSError)):
            inspect_image(self.path)

    def test_invalid_input_rejected_before_model_load(self):
        self.path.write_bytes(b'not an image')
        with patch('privacy_guard.pipeline.load_document_model') as model:
            with self.assertRaises(ValueError):
                protect_with_yolo(self.path, 'unused.pt', self.keys/'public.pem', self.folder/'out',
                                  image_password=b'forensics-image-password')
            model.assert_not_called()
        self.assertFalse((self.folder/'out').exists())

    def test_outside_channel_changes_rejected(self):
        original = self.image.convert('RGBA')
        protected = original.copy()
        protected.paste((0, 0, 0, 255), (1, 1, 5, 5))
        protected.putpixel((10, 9), (99, 50, 25, 255))
        with self.assertRaisesRegex(ValueError, 'outside'):
            verify_protected_image(original, png_bytes(protected), [[1, 1, 5, 5]])

    def test_protected_metadata_is_rejected(self):
        buffer = io.BytesIO()
        metadata = PngImagePlugin.PngInfo()
        metadata.add_text('comment', 'secret')
        self.image.save(buffer, format='PNG', pnginfo=metadata)
        with self.assertRaisesRegex(ValueError, 'metadata'):
            verify_protected_image(self.image, buffer.getvalue(), [[1, 1, 5, 5]])

    def test_authenticated_record_and_untrusted_readable_copy(self):
        image, record = inspect_image(self.path)
        out = self.folder / 'protected'
        image_password = b'forensics-image-password'
        protect_image(image, [[1, 1, 5, 5]], out, self.keys/'public.pem', inspection=record,
                      image_password=image_password)
        payload = unlock_payload(decrypt_bytes((out/'regions.islenc').read_bytes(),
                                               self.keys/'private.pem', self.password), image_password)
        length = struct.unpack('>I', payload[:4])[0]
        manifest = json.loads(payload[4:4+length])
        self.assertEqual(manifest['forensics']['input_inspection'], record)
        # A changed readable report must not influence restoration evidence.
        (out/'forensic_report.json').write_text('{"forged":true}')
        report = restore(out/'protected.png', out/'regions.islenc', self.folder/'restored.png',
                         self.keys/'private.pem', self.password, image_password=image_password)
        self.assertEqual(report['authenticated_forensic_record']['input_inspection'], record)
        self.assertTrue(report['protection_checks']['outside_region_unchanged'])
        # Legacy manifests still restore and explicitly report missing forensic evidence.
        del manifest['forensics']
        metadata = json.dumps(manifest).encode()
        legacy = struct.pack('>I', len(metadata)) + metadata + payload[4+length:]
        (out/'legacy.islenc').write_bytes(encrypt_bytes(protect_payload(legacy, image_password),
                                                    self.keys/'public.pem'))
        report = restore(out/'protected.png', out/'legacy.islenc', self.folder/'legacy.png',
                         self.keys/'private.pem', self.password, image_password=image_password)
        self.assertEqual(report['forensic_record_status'], 'legacy_not_recorded')

    def test_record_must_match_pixels(self):
        image, record = inspect_image(self.path)
        image.putpixel((0, 0), (0, 0, 0))
        with self.assertRaisesRegex(ValueError, 'Inspection record'):
            protect_image(image, [[1,1,5,5]], self.folder/'out', self.keys/'public.pem',
                          inspection=record, image_password=b'forensics-image-password')
        self.assertFalse((self.folder/'out').exists())
