import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("local_tool", HERE / "tool.py")
tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)

class Tests(unittest.TestCase):
    def good(self):
        return json.loads((HERE / "examples/pass.json").read_text())
    def codes(self, data):
        return [item['code'] for item in tool.audit(data)['findings']]
    def test_pass(self):
        self.assertEqual(tool.audit(self.good())['status'], 'pass')
    def test_findings(self):
        self.assertEqual(tool.audit(json.loads((HERE / "examples/fail.json").read_text()))['status'], 'findings')
    def test_malformed_shape(self):
        with self.assertRaises(tool.BadInput): tool.audit([])
    def test_cli_examples(self):
        for name, expected in [('pass',0),('fail',1)]:
            result = subprocess.run([sys.executable, str(HERE/'tool.py'), str(HERE/f'examples/{name}.json')], capture_output=True, text=True)
            self.assertEqual(result.returncode, expected, result.stdout+result.stderr)
            self.assertEqual(json.loads(result.stdout)['schema_version'], 1)
    def test_cli_malformed(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'bad.json'
            for text in ['{', '{"x":1,"x":2}', '{"x":NaN}']:
                path.write_text(text)
                result = subprocess.run([sys.executable, str(HERE/'tool.py'), str(path)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(json.loads(result.stdout)['status'], 'error')
    def test_cli_bad_args(self):
        result = subprocess.run([sys.executable, str(HERE/'tool.py'), '--unknown'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2); self.assertEqual(json.loads(result.stdout)['status'], 'error')
    def test_size_limit(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'big.json'; path.write_text(' '* (tool.MAX_BYTES+1))
            with self.assertRaises(tool.BadInput): tool.load_json(path)

    def test_budget_stops_expansion(self):
        data = self.good(); data['max_artifacts'] = 2
        result = tool.audit(data)
        self.assertIn('artifact_budget_exceeded', [x['code'] for x in result['findings']]); self.assertEqual(result['summary']['generated'], 0)
    def test_path_characters(self):
        data = self.good(); data['template'] = '../{os}-{arch}'
        self.assertIn('unsafe_artifact_name', self.codes(data))
    def test_duplicate_values(self):
        data = self.good(); data['matrix']['os'] = ['linux','linux']
        self.assertIn('name_collision', self.codes(data))
    def test_case_collision(self):
        data = self.good(); data['matrix']['os'] = ['linux','Linux']
        self.assertIn('portable_name_collision', self.codes(data))
    def test_bad_field(self):
        data = self.good(); data['template'] = '{os.upper}'
        with self.assertRaises(tool.BadInput): tool.audit(data)
    def test_bad_format_spec(self):
        data = self.good(); data['template'] = '{os:>40}'
        with self.assertRaises(tool.BadInput): tool.audit(data)
    def test_empty_dimension(self):
        data = self.good(); data['matrix']['os'] = []
        with self.assertRaises(tool.BadInput): tool.audit(data)
    def test_reserved_name(self):
        data = {'matrix':{'x':['CON']},'template':'{x}.zip'}
        self.assertIn('unsafe_artifact_name', self.codes(data))

    def test_long_names_bounded_output(self):
        data = {'matrix':{'x':['a'*128,'a'*128]},'template':'{x}'*300}
        result = tool.audit(data)
        self.assertEqual(result['summary']['names'], [None, None])
        self.assertIn('name_collision', [f['code'] for f in result['findings']])
    def test_backslash_and_controls(self):
        for value in ['a\\b','a\x01b']:
            self.assertIn('unsafe_artifact_name', self.codes({'matrix':{'x':[value]},'template':'{x}'}))
    def test_cli_giant_number(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'bad.json'; path.write_text('{"x":'+ '9'*5000 + '}')
            result = subprocess.run([sys.executable,str(HERE/'tool.py'),str(path)],capture_output=True,text=True)
            self.assertEqual(result.returncode, 2); self.assertEqual(json.loads(result.stdout)['status'], 'error')

if __name__ == "__main__": unittest.main()
