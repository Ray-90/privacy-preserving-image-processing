"""Run with: python -m unittest -v test_encryption.py"""
import base64
from pathlib import Path
import tempfile
import unittest

import encryption as enc


class EncryptionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workspace = tempfile.TemporaryDirectory()
        cls.root = Path(cls.workspace.name)
        cls.password = b'test-only-password'
        cls.keys = enc.generate_keys(cls.root / 'keys', cls.password)
        cls.other = enc.generate_keys(cls.root / 'other', cls.password)

    @classmethod
    def tearDownClass(cls):
        cls.workspace.cleanup()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=self.root)
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name)
        self.source = self.folder / 'original.png'
        self.source.write_bytes(base64.b64decode(
            'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aLXcAAAAASUVORK5CYII='))
        self.encrypted = self.folder / 'image.islenc'
        self.output = self.folder / 'restored.png'
        enc.encrypt_file(self.source, self.encrypted, self.keys / 'public.pem')

    def decrypt(self, source=None, keys=None, password=None):
        enc.decrypt_file(source or self.encrypted, self.output,
                         (keys or self.keys) / 'private.pem',
                         password or self.password)

    def test_image_round_trip(self):
        self.decrypt()
        self.assertEqual(self.source.read_bytes(), self.output.read_bytes())

    def test_fresh_encryption_each_time(self):
        other = self.folder / 'second.islenc'
        enc.encrypt_file(self.source, other, self.keys / 'public.pem')
        self.assertNotEqual(self.encrypted.read_bytes(), other.read_bytes())

    def test_tampering_and_truncation_leave_no_plaintext(self):
        data = self.encrypted.read_bytes()
        # Version, length, wrapped key, nonce, ciphertext and authentication tag.
        for index in [0, 8, 20, 394, 410, len(data) - 1]:
            with self.subTest(index=index):
                damaged = bytearray(data)
                damaged[index] ^= 1
                bad = self.folder / 'damaged.islenc'
                bad.write_bytes(damaged)
                with self.assertRaises(ValueError):
                    self.decrypt(source=bad)
                self.assertFalse(self.output.exists())
        for length in [0, 9, 100, len(data) - 1]:
            bad.write_bytes(data[:length])
            with self.assertRaises(ValueError):
                self.decrypt(source=bad)
            self.assertFalse(self.output.exists())

    def test_wrong_key_and_password(self):
        with self.assertRaises(ValueError):
            self.decrypt(keys=self.other)
        with self.assertRaises(ValueError):
            self.decrypt(password=b'wrong-password')
        self.assertFalse(self.output.exists())

    def test_refuse_overwrite(self):
        self.output.write_bytes(b'keep this')
        with self.assertRaises(FileExistsError):
            self.decrypt()
        self.assertEqual(self.output.read_bytes(), b'keep this')
        before = self.encrypted.read_bytes()
        with self.assertRaises(FileExistsError):
            enc.encrypt_file(self.source, self.encrypted, self.keys / 'public.pem')
        self.assertEqual(before, self.encrypted.read_bytes())

    def test_source_and_destination_same(self):
        before = self.source.read_bytes()
        with self.assertRaises(FileExistsError):
            enc.encrypt_file(self.source, self.source, self.keys / 'public.pem')
        self.assertEqual(before, self.source.read_bytes())

    def test_size_limit(self):
        with self.assertRaises(ValueError):
            enc.read_bounded(self.source, 2)

    def test_private_key_is_encrypted(self):
        self.assertIn(b'BEGIN ENCRYPTED PRIVATE KEY', (self.keys / 'private.pem').read_bytes())


if __name__ == '__main__':
    unittest.main()
