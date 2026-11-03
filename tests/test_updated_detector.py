from privacy_guard.detection.model import load_document_model
from privacy_guard.detection.dataset import check_dataset
from privacy_guard.detection.metrics import metrics_summary
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import unittest

class UpdatedDetectorTests(unittest.TestCase):
    def test_old_single_class_checkpoint_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            weights=Path(tmp)/'old.pt'; weights.touch()
            with patch('privacy_guard.detection.model.load_model', return_value=SimpleNamespace(names={0:'Credit_card'},task='detect')):
                with self.assertRaisesRegex(ValueError,'old Credit_card'):
                    load_document_model(weights)

    def test_metric_indices_respect_missing_class(self):
        metrics=SimpleNamespace(mean_results=lambda:[.8,.7,.6,.5],ap_class_index=[0,2],
                                class_result=lambda i:[[.9,.8,.7,.6],[.5,.4,.3,.2]][i])
        report=metrics_summary(metrics)
        self.assertIsNone(report['per_class']['pan_card'])
        self.assertEqual(report['per_class']['payment_card']['mAP50'],.3)

    def test_invalid_class_label_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/'data.yaml').write_text('nc: 3\nnames: [aadhaar_card, pan_card, payment_card]\n')
            for split in ['train','valid']:
                (root/split/'images').mkdir(parents=True);(root/split/'labels').mkdir()
                (root/split/'images/a.jpg').touch()
                (root/split/'labels/a.txt').write_text('9 0.5 0.5 0.4 0.4\n')
            with self.assertRaisesRegex(ValueError,'Invalid class'):
                check_dataset(root)

if __name__=='__main__':unittest.main()
