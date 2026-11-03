import contextlib
import io
import json
import shutil
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from PIL import Image

from privacy_guard.cli import main
from privacy_guard.crypto.keys import generate_keys
from privacy_guard.crypto.hybrid import decrypt_bytes, encrypt_bytes
from privacy_guard.crypto.image_password import unlock_payload
from privacy_guard.image_store import ImageStore
from privacy_guard.pipeline import protect_image


class SimpleImageStoreTests(unittest.TestCase):
    def test_delete_only_selected_entry_and_refuse_unexpected_files(self):
        with tempfile.TemporaryDirectory() as folder:
            store = Path(folder) / 'protected_images'
            store.mkdir()
            ids = ['img-' + c * 32 for c in ('a', 'b')]
            for image_id in ids:
                bundle = store / image_id
                bundle.mkdir()
                (bundle / 'image.json').write_text(json.dumps({
                    'id': image_id, 'name': 'Synthetic', 'created_utc': '2026-11-03T00:00:00Z'}))
                (bundle / 'protected.png').write_bytes(b'preview')
                (bundle / 'regions.islenc').write_bytes(b'encrypted')
            extra = store / ids[0] / 'notes.txt'
            extra.write_text('keep')
            with self.assertRaisesRegex(ValueError, 'unexpected contents'):
                ImageStore(store).delete(ids[0])
            self.assertTrue(extra.exists())
            extra.unlink()
            self.assertEqual(ImageStore(store).delete(ids[0])['id'], ids[0])
            self.assertFalse((store / ids[0]).exists())
            self.assertEqual([r['id'] for r in ImageStore(store).list()], [ids[1]])
            with self.assertRaisesRegex(ValueError, 'Invalid image ID'):
                ImageStore(store).delete('../keys')

    def test_add_list_restore_with_shared_key_and_wrong_password(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            store = root / 'protected_images'
            generate_keys(root / 'keys', b'correct-password')
            images = []
            expected_pixels = []
            for i in range(2):
                source = root / f'original_{i}.png'
                Image.new('RGB', (14, 12), (i * 73 + 10, 21, 38)).save(source)
                images.append(source)
                with Image.open(source) as original:
                    expected_pixels.append(original.tobytes())
            model = SimpleNamespace(predict=lambda **kwargs: [SimpleNamespace(orig_shape=(12, 14))])
            image_passwords = [b'first-image-password', b'second-image-password']
            with patch('privacy_guard.pipeline.load_document_model', return_value=model), \
                 patch('privacy_guard.pipeline.box_records', return_value=[{'xyxy':[1, 1, 7, 7]}]):
                records = [ImageStore(store, create=True).add(image, 'fake.pt', root/'keys/public.pem',
                                                              name=f'Synthetic {index}',
                                                              image_password=image_passwords[index])
                           for index, image in enumerate(images)]
            self.assertNotEqual(records[0]['id'], records[1]['id'])
            self.assertEqual([r['id'] for r in ImageStore(store).list()], [r['id'] for r in records])
            self.assertFalse((store/'catalogue.sqlite3').exists())
            self.assertTrue(all(not image.exists() for image in images))
            for index, record in enumerate(records):
                output = root / f'restored_{index}.png'
                report = ImageStore(store).restore(record['id'], output,
                                                   root/'keys/private.pem', b'correct-password',
                                                   image_password=image_passwords[index])
                self.assertEqual(report['authenticated_image_id'], record['id'])
                with Image.open(output) as restored:
                    self.assertEqual(restored.tobytes(), expected_pixels[index])
            with self.assertRaisesRegex(ValueError, 'Incorrect private-key password'):
                ImageStore(store).restore(records[0]['id'], root/'wrong.png',
                                          root/'keys/private.pem', b'wrong-password',
                                          image_password=image_passwords[0])
            self.assertFalse((root/'wrong.png').exists())
            with self.assertRaisesRegex(ValueError, 'Incorrect image password'):
                ImageStore(store).restore(records[0]['id'], root/'wrong_image.png',
                                          root/'keys/private.pem', b'correct-password',
                                          image_password=image_passwords[1])
            self.assertFalse((root/'wrong_image.png').exists())
            with self.assertRaisesRegex(ValueError, 'Invalid image ID'):
                ImageStore(store).restore('../keys', root/'escaped.png',
                                          root/'keys/private.pem', b'correct-password',
                                          image_password=image_passwords[0])
            first = store / records[0]['id']
            second = store / records[1]['id']
            shutil.copyfile(second/'protected.png', first/'protected.png')
            shutil.copyfile(second/'regions.islenc', first/'regions.islenc')
            with self.assertRaisesRegex(ValueError, 'Encrypted image ID'):
                ImageStore(store).restore(records[0]['id'], root/'swapped.png',
                                          root/'keys/private.pem', b'correct-password',
                                          image_password=image_passwords[1])
            self.assertFalse((root/'swapped.png').exists())

    def test_failed_detection_keeps_original(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / 'source.png'
            Image.new('RGB', (10, 10), (10, 20, 30)).save(source)
            generate_keys(root / 'keys', b'test-password')
            model = SimpleNamespace(predict=lambda **kwargs: [SimpleNamespace(orig_shape=(10, 10))])
            with patch('privacy_guard.pipeline.load_document_model', return_value=model), \
                 patch('privacy_guard.pipeline.box_records', return_value=[]):
                with self.assertRaisesRegex(ValueError, 'No detected documents'):
                    ImageStore(root / 'store', create=True).add(
                        source, 'fake.pt', root / 'keys/public.pem',
                        image_password=b'failed-detection-pass')
            self.assertTrue(source.exists())

    def test_preexisting_authenticated_bundle_without_image_password_restores(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            store = root / 'protected_images'
            store.mkdir()
            keys = generate_keys(root / 'keys', b'private-key-password')
            image_id = 'img-' + 'b' * 32
            record = {'id': image_id, 'name': 'Existing image',
                      'created_utc': '2026-10-15T12:00:00+00:00'}
            image = Image.new('RGB', (12, 12), (45, 55, 65))
            bundle = store / image_id
            protect_image(image, [[2, 2, 8, 8]], bundle, keys / 'public.pem',
                          image_id=image_id, image_password=b'temporary-image-password')
            sidecar = bundle / 'regions.islenc'
            wrapped = decrypt_bytes(sidecar.read_bytes(), keys / 'private.pem', b'private-key-password')
            old_payload = unlock_payload(wrapped, b'temporary-image-password')
            sidecar.write_bytes(encrypt_bytes(old_payload, keys / 'public.pem'))
            (bundle / 'image.json').write_text(json.dumps(record))
            output = root / 'restored.png'
            report = ImageStore(store).restore(image_id, output, keys / 'private.pem',
                                                b'private-key-password', image_password=b'')
            self.assertEqual(report['image_password_authentication'], 'not_present')
            with Image.open(output) as restored:
                self.assertEqual(restored.tobytes(), image.tobytes())

    def test_cli_lists_and_does_not_store_plaintext_inside_store(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            store = root / 'protected_images'
            store.mkdir()
            record = {'id': 'img-' + '1'*32, 'name': 'Demo', 'created_utc': '2026-10-15T12:00:00+00:00'}
            bundle = store / record['id']
            bundle.mkdir()
            (bundle/'image.json').write_text(json.dumps(record))
            with contextlib.redirect_stdout(io.StringIO()) as output:
                main(['image-list', '--store', str(store)])
            self.assertEqual(json.loads(output.getvalue()), [record])
            with self.assertRaisesRegex(ValueError, 'outside'):
                ImageStore(store).restore(record['id'], store/'plaintext.png', 'unused.pem', b'secret',
                                          image_password=b'example-image-password')

    def test_bundle_without_authenticated_id_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            store = root/'protected_images'
            store.mkdir()
            keys = generate_keys(root/'keys', b'test-only-password')
            record = {'id': 'img-' + 'a'*32, 'name': 'Old image',
                      'created_utc': '2026-10-15T12:00:00+00:00'}
            image = Image.new('RGB', (12, 12), (45, 55, 65))
            bundle = store / record['id']
            protect_image(image, [[2, 2, 8, 8]], bundle, keys/'public.pem',
                          image_password=b'example-image-password')
            (bundle/'image.json').write_text(json.dumps(record))
            output = root/'restored.png'
            with self.assertRaisesRegex(ValueError, 'Encrypted image ID'):
                ImageStore(store).restore(record['id'], output, keys/'private.pem',
                                          b'test-only-password', image_password=b'example-image-password')
            self.assertFalse(output.exists())
