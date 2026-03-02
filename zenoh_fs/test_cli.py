import unittest
from zenoh_fs.FileServer import FileServer

class TestNormalizePath(unittest.TestCase):
    def setUp(self):
        self.server = FileServer()
        self.server.zenoh_path = "hostname/files"

    def test_path_matrix(self):
        """
        A matrix of test cases focusing on duplicate and mixed paths.
        Uses subTest to run each case as an individual test.
        """

        # Matrix format: (input_path, expected_output)
        test_cases = [
            # Standard controls
            ("hostname/files/read/file.txt", "/file.txt"),
            ("hostname/files/write/file.txt", "/file.txt"),

            # 1. Duplicate structural verbs (Verb acts as Verb then Dir)
            ("hostname/files/read/read/read.txt", "/read/read.txt"), # Strip first read
            ("hostname/files/write/write/write.txt", "/write/write.txt"), # Strip first write

            # 2. Mixed verbs (Verb vs Directory name)
            # Reading a file inside a directory named "write" or vice versa
            ("hostname/files/read/write/file.txt", "/write/file.txt"), 
            ("hostname/files/write/read/file.txt", "/read/file.txt"),

            # 3. Tickets combined with Mixed Verbs
            ("hostname/files/ticket/read/write/file.txt", "/write/file.txt"),
            ("hostname/files/ticket/write/read/file.txt", "/read/file.txt"),
            ("hostname/files/ticket/read/read/file.txt", "/read/file.txt"),

            # 4. Deep nesting with duplicates
            ("hostname/files/read/path/read/file.txt", "/path/read/file.txt"),
            ("hostname/files/write/path/write/file.txt", "/path/write/file.txt"),

            # 5. Root-level edge cases
            ("hostname/files/read", "/"), # Verb only
            ("hostname/files/write", "/"), # Verb only
            ("hostname/files/read/read", "/read"), # Verb + Dir named read
            ("hostname/files/write/write", "/write"), # Verb + Dir named write

            # 6. Ticket at root
            ("hostname/files/ticket/read", "/"), # Ticket + Verb only
        ]

        for input_path, expected in test_cases:
            with self.subTest(input_path=input_path, expected=expected):
                result = self.server.normalize_path(input_path)
                self.assertEqual(
                    result, 
                    expected, 
                    f"Failed for input: '{input_path}'. Expected '{expected}' but got '{result}'"
                )

import time


ZENOH_PATH = "test/files"


if __name__ == '__main__':
    unittest.main(buffer=False)
