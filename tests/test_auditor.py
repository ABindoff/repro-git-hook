import os
import tempfile
import unittest
from pathlib import Path
import sys

# Add parent directory to path so we can import auditor
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from auditor import check_secrets, check_python_file, check_r_file, check_env_pinned

class TestAuditor(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _create_temp_file(self, filename, content):
        file_path = self.dir_path / filename
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)
        return str(file_path)

    # --- Test Secrets Scanner ---
    def test_check_secrets_finds_rsa_key(self):
        filepath = self._create_temp_file("test_secret.txt", "Some text\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n")
        issues = check_secrets(filepath)
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["rule"], "no-secrets")

    def test_check_secrets_clean_file(self):
        filepath = self._create_temp_file("clean.txt", "Hello world\nNothing to see here.")
        issues = check_secrets(filepath)
        self.assertEqual(len(issues), 0)

    # --- Test Python Linter ---
    def test_python_missing_seed(self):
        filepath = self._create_temp_file("test.py", "import random\nprint(random.randint(1, 10))")
        issues = check_python_file(filepath)
        self.assertTrue(any(i["rule"] == "random-seed" for i in issues))

    def test_python_has_seed(self):
        filepath = self._create_temp_file("test.py", "import random\nrandom.seed(42)\nprint(random.randint(1, 10))")
        issues = check_python_file(filepath)
        self.assertFalse(any(i["rule"] == "random-seed" for i in issues))

    def test_python_hardcoded_path(self):
        filepath = self._create_temp_file("test.py", 'file_path = "C:\\\\Users\\\\Bob\\\\data.csv"')
        issues = check_python_file(filepath)
        self.assertTrue(any(i["rule"] == "no-hardcoded-paths" for i in issues))

    def test_python_inplace_data_mutation(self):
        filepath = self._create_temp_file("test.py", 'path = "data/raw/data.csv"')
        issues = check_python_file(filepath)
        self.assertTrue(any(i["rule"] == "no-inplace-data-mutation" for i in issues))

    # --- Test R Linter ---
    def test_r_missing_seed(self):
        filepath = self._create_temp_file("test.R", "data <- rnorm(100, 0, 1)")
        issues = check_r_file(filepath)
        self.assertTrue(any(i["rule"] == "random-seed" for i in issues))

    def test_r_has_seed(self):
        filepath = self._create_temp_file("test.R", "set.seed(123)\ndata <- rnorm(100, 0, 1)")
        issues = check_r_file(filepath)
        self.assertFalse(any(i["rule"] == "random-seed" for i in issues))

    def test_r_hardcoded_path(self):
        filepath = self._create_temp_file("test.R", 'df <- read.csv("/home/user/data.csv")')
        issues = check_r_file(filepath)
        self.assertTrue(any(i["rule"] == "no-hardcoded-paths" for i in issues))

    # --- Test Env Pinned ---
    def test_env_pinned_unpinned(self):
        self._create_temp_file("requirements.txt", "pandas>=1.0.0\nnumpy\nscipy==1.10.0")
        issues = check_env_pinned(self.dir_path)
        # Should flag pandas and numpy
        self.assertEqual(len(issues), 2)
        self.assertEqual(issues[0]["rule"], "env-pinned")

    def test_env_pinned_clean(self):
        self._create_temp_file("requirements.txt", "pandas==1.0.0\nnumpy==1.24.0")
        issues = check_env_pinned(self.dir_path)
        self.assertEqual(len(issues), 0)

if __name__ == "__main__":
    unittest.main()
