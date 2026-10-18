import pathlib
import runpy
import unittest


PREPARE = runpy.run_path(str(pathlib.Path(__file__).with_name("prepare-agent-tls.py")))["prepare"]
ARTIFACTS = pathlib.Path(__file__).resolve().parent.parent / "artifacts"


class TLSPreflightTests(unittest.TestCase):
    def test_rejects_loopback_without_creating_output(self):
        destination = ARTIFACTS / "uncreated-agent-tls"
        with self.assertRaises(ValueError):
            PREPARE("127.0.0.1", destination)
        self.assertFalse(destination.exists())

    def test_refuses_existing_directory(self):
        with self.assertRaises(ValueError):
            PREPARE("192.168.193.129", ARTIFACTS)

    def test_rejects_public_address(self):
        with self.assertRaises(ValueError):
            PREPARE("8.8.8.8", ARTIFACTS / "uncreated-agent-tls")


if __name__ == "__main__":
    unittest.main()
