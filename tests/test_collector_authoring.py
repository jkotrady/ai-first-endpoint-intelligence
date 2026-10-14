import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
def module(name,file):
    spec=importlib.util.spec_from_file_location(name,ROOT/'scripts'/file)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
new=module('new_collector','new-collector.py')
stage=module('stage_release','stage-agent-release.py')
class Authoring(unittest.TestCase):
    def fixture(self,folder):
        root=Path(folder)
        for file in ['internal/console/collectors.json','collectors/catalog.json']:
            p=root/file;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes((ROOT/file).read_bytes())
        return root
    def test_draft_never_enables_or_replaces_collector(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'work') as folder:
            root=self.fixture(folder);before=(root/'collectors/catalog.json').read_bytes()
            p=new.create_draft(root,'F03')
            self.assertIn('collector_not_implemented',(p/'F03_collection.c').read_text())
            self.assertEqual(before,(root/'collectors/catalog.json').read_bytes())
            self.assertFalse((root/'collectors/windows/F03_collection.c').exists())
            for ident in ['F01','F99','../F03']:
                with self.assertRaises(ValueError):new.create_draft(root,ident)
            with self.assertRaises(FileExistsError):new.create_draft(root,'F03')
    def test_release_refuses_corruption_and_overwrite(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'work') as folder:
            root=self.fixture(folder);bin=root/'work/bin';bin.mkdir(parents=True)
            data=b'fixture';digest=stage.hashlib.sha256(data).hexdigest()
            m=dict(binary_sha256=digest,binary_size=len(data),source_zip_sha256=digest,source_zip_size=len(data),collectors=json.loads((root/'collectors/catalog.json').read_text()))
            (bin/'agent-build.json').write_text(json.dumps(m))
            for f in ['forensics-agent-x86.exe','forensics-agent-source.zip']:(bin/f).write_bytes(data)
            dest=stage.stage(root,'test');self.assertEqual(len(list(dest.iterdir())),3)
            with self.assertRaises(FileExistsError):stage.stage(root,'test')
            (bin/'forensics-agent-x86.exe').write_bytes(b'corrupt')
            with self.assertRaises(ValueError):stage.stage(root,'bad')
            self.assertFalse((root/'work/releases/bad').exists())
            dest.chmod(0o700)
            for f in dest.iterdir():f.chmod(0o600)
