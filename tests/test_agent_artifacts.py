import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('artifacts',ROOT/'scripts/agent_artifacts.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class AgentArtifacts(unittest.TestCase):
    def test_bundle_explicit_sources_and_reproducibility(self):
        catalog,data,hashes,fingerprint=m.inputs()
        first=m.bundle(data)
        self.assertEqual(first,m.bundle(dict(reversed(list(data.items())))))
        with zipfile.ZipFile(io.BytesIO(first)) as z:
            self.assertEqual(set(z.namelist()),set(m.FIXED+[e['source'] for e in catalog]))
            for name in z.namelist():
                self.assertFalse(name.startswith(('work/','tools/')))
                self.assertEqual(m.digest(z.read(name)),hashes[name])
        self.assertEqual(len(fingerprint),64)
    def test_catalog_cannot_include_private_path_or_duplicate(self):
        catalog=json.loads((ROOT/'collectors/catalog.json').read_text())
        with tempfile.TemporaryDirectory(dir=ROOT/'work') as d:
            root=Path(d);(root/'collectors').mkdir()
            for mutation in ['path','duplicate','function']:
                edited=json.loads(json.dumps(catalog))
                if mutation=='path':edited[0]['source']='work/private/windows-license-keys.json'
                if mutation=='duplicate':edited.append(edited[0])
                if mutation=='function':edited[0]['entrypoint']='system'
                (root/'collectors/catalog.json').write_text(json.dumps(edited))
                with self.assertRaises(ValueError):m.inputs(root)

if __name__=='__main__':unittest.main()
