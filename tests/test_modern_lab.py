import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('modern_lab',ROOT/'tools/modern_lab.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class ModernIntake(unittest.TestCase):
    def test_missing_media_is_blocker(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'work') as folder:
            value,errors=m.verify_media(Path(folder),{'image_manifest':'missing.json'})
            self.assertIsNone(value);self.assertEqual(errors,['media_manifest_missing'])
    def test_rejects_wrong_edition_hash_size_and_outside_path(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'work') as folder:
            root=Path(folder);image=b'fake fixture; never Windows evidence'
            (root/'fixture.iso').write_bytes(image)
            p=dict(product_edition='Windows 10 Pro',version='22H2',build_family='10.0.19045',architecture='x86',image_manifest='media.json')
            good=dict(p,image='fixture.iso',size=len(image),sha256=m.hashlib.sha256(image).hexdigest(),source_reference='synthetic unit fixture')
            def check(value):
                (root/'media.json').write_text(json.dumps(value));return m.verify_media(root,p)
            self.assertEqual(check(good)[1],[])
            for field,value in [('product_edition','Windows 10 Home'),('architecture','x64'),('sha256','0'*64),('size',1),('image','../../secret')]:
                self.assertTrue(check(dict(good,**{field:value}))[1],field)
    def test_profiles_preserve_exact_selected_matrix(self):
        profiles=json.loads((ROOT/'tools/lab/modern-windows.json').read_text())
        matrix={p['id']:p for p in json.loads((ROOT/'outputs/windows-matrix.json').read_text())['profiles']}
        self.assertEqual([p['id'] for p in profiles],['W04','W05','W06','W07','W08','W09','W10','W11','W12'])
        for p in profiles:
            for key in ('product_edition','version','build_family','architecture'):self.assertEqual(p[key],matrix[p['id']][key])
            self.assertEqual(p['network'],'none')
            if p['id'] in ('W10','W11','W12'):
                self.assertEqual(p['tpm'],'2.0');self.assertEqual(p['firmware'],'uefi_secure_boot')

if __name__=='__main__':unittest.main()
