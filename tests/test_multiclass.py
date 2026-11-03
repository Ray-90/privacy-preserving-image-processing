from privacy_guard.detection.model import box_records
from privacy_guard.detection.dataset import dataset_config
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
import numpy as np

class MultiClassTests(unittest.TestCase):
    def test_prediction_class_names_are_not_hardcoded(self):
        names={0:'aadhaar_card',1:'pan_card',2:'payment_card'}
        boxes=[SimpleNamespace(xyxy=np.array([[1,2,6,8]]),cls=np.array(i),conf=np.array(.8)) for i in range(3)]
        records=box_records(SimpleNamespace(orig_shape=(10,10),boxes=boxes,names=names))
        self.assertEqual([r['class_name'] for r in records],list(names.values()))
        self.assertEqual([r['class_id'] for r in records],[0,1,2])

    def test_three_class_dataset_configuration(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/'data.yaml').write_text("nc: 3\nnames: [aadhaar_card, pan_card, payment_card]\n")
            for split in ['train','valid','test']:
                (root/split/'images').mkdir(parents=True)
                (root/split/'labels').mkdir()
                (root/split/'images/example.jpg').touch()
                (root/split/'labels/example.txt').write_text('2 0.5 0.5 0.5 0.5\n')
            cfg=dataset_config(root)
            self.assertEqual(cfg['nc'],3)
            self.assertEqual(cfg['names'],['aadhaar_card','pan_card','payment_card'])
            self.assertTrue(Path(cfg['test']).is_absolute())

if __name__=='__main__':unittest.main()
