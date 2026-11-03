import unittest

from privacy_guard.crypto.image_password import protect_payload, unlock_payload


class ImagePasswordTests(unittest.TestCase):
    def test_round_trip_and_randomized_envelopes(self):
        password = b'long-secret-image-password'
        payload = b'example private region bytes'
        first = protect_payload(payload, password)
        second = protect_payload(payload, password)
        self.assertNotEqual(first, second)
        self.assertEqual(unlock_payload(first, password), payload)
        self.assertEqual(unlock_payload(second, password), payload)

    def test_wrong_password_and_tampering_fail(self):
        package = protect_payload(b'private pixels', b'correct-image-password')
        with self.assertRaisesRegex(ValueError, 'Incorrect image password'):
            unlock_payload(package, b'incorrect-image-password')
        changed = bytearray(package)
        changed[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'damaged encrypted image'):
            unlock_payload(bytes(changed), b'correct-image-password')

    def test_short_password_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'at least 8'):
            protect_payload(b'private pixels', b'short')
        self.assertEqual(unlock_payload(protect_payload(b'pixels', b'eight8ok'), b'eight8ok'), b'pixels')
