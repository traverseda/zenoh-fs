import unittest
import subprocess
import sys
import tempfile
import os
import time

from zenoh_fs.cli import ZenohFS, ZenohFile

ZENOH_PATH = "test/files"


class TestZenohFSReadIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp()

        cls.file_content = b"hello from zenoh" * 64  # 1024 bytes
        with open(os.path.join(cls.tmpdir, "file.txt"), "wb") as f:
            f.write(cls.file_content)

        os.makedirs(os.path.join(cls.tmpdir, "subdir"), exist_ok=True)
        with open(os.path.join(cls.tmpdir, "subdir", "nested.txt"), "wb") as f:
            f.write(b"nested content")

        cls.server_proc = subprocess.Popen(
            [sys.executable, "-m", "zenoh_fs.cli", "expose", cls.tmpdir, "--zenoh-path", ZENOH_PATH],
            stdout=sys.stdout,
            stderr=sys.stderr,
        )

        time.sleep(1)

        if cls.server_proc.poll() is not None:
            raise RuntimeError(f"Server failed to start, exit code: {cls.server_proc.returncode}")

        cls.fs = ZenohFS(ZENOH_PATH)

    @classmethod
    def tearDownClass(cls):
        cls.fs.session.close()
        cls.server_proc.terminate()
        cls.server_proc.wait(timeout=5)

    def setUp(self):
        if self.server_proc.poll() is not None:
            self.fail(f"Server crashed before test, exit code: {self.server_proc.returncode}")

    def tearDown(self):
        if self.server_proc.poll() is not None:
            self.fail(f"Server crashed during test, exit code: {self.server_proc.returncode}")

    # --- info ---

    def test_info_file(self):
        result = self.fs.info("/file.txt")
        self.assertEqual(result["type"], "file")
        self.assertEqual(result["size"], len(self.file_content))
        self.assertEqual(result["name"], "/file.txt")

    def test_info_directory(self):
        result = self.fs.info("/subdir")
        self.assertEqual(result["type"], "directory")

    def test_info_root(self):
        result = self.fs.info("/")
        self.assertEqual(result["type"], "directory")

    def test_info_not_found(self):
        with self.assertRaises(FileNotFoundError):
            self.fs.info("/does_not_exist.txt")

    # --- ls ---

    def test_ls_root_detail_false(self):
        result = self.fs.ls("/", detail=False)
        self.assertIn("/file.txt", result)
        self.assertIn("/subdir", result)

    def test_ls_root_detail_true(self):
        result = self.fs.ls("/", detail=True)
        names = [e["name"] for e in result]
        self.assertIn("/file.txt", names)
        for entry in result:
            self.assertIn("name", entry)
            self.assertIn("size", entry)
            self.assertIn("type", entry)

    def test_ls_subdir(self):
        result = self.fs.ls("/subdir", detail=False)
        self.assertIn("/subdir/nested.txt", result)

    def test_ls_not_found(self):
        with self.assertRaises(FileNotFoundError):
            self.fs.ls("/nonexistent")

    # --- open / read ---

    def test_open_read_full(self):
        with self.fs.open("/file.txt", mode="rb") as f:
            data = f.read()
        self.assertEqual(data, self.file_content)

    def test_open_read_partial(self):
        with self.fs.open("/file.txt", mode="rb") as f:
            f.seek(5)
            data = f.read(5)
        self.assertEqual(data, self.file_content[5:10])

    def test_open_write_raises(self):
        with self.assertRaises(NotImplementedError):
            self.fs.open("/file.txt", mode="wb")

    def test_open_append_raises(self):
        with self.assertRaises(NotImplementedError):
            self.fs.open("/file.txt", mode="ab")

    def test_open_size_matches_info(self):
        info = self.fs.info("/file.txt")
        f = self.fs.open("/file.txt", mode="rb")
        self.assertEqual(f.size, info["size"])
        f.close()

    def test_read_nested_file(self):
        with self.fs.open("/subdir/nested.txt", mode="rb") as f:
            data = f.read()
        self.assertEqual(data, b"nested content")


if __name__ == "__main__":
    unittest.main(verbosity=2, failfast=True)
