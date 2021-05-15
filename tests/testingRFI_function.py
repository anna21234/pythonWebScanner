import unittest
import pythonScannerCMD

testing_url = "http://172.16.218.131/dvwa/vulnerabilities/fi/?page=include.php"
returned_msg_success = "Remote file accessed successfully"
returned_msg_fail = "Sorry, no remote files found"


class RFITestCase(unittest.TestCase):
    def test_remote_file_inclusion(self):
        actual = pythonScannerCMD.scan_for_rfi(testing_url)
        expected = returned_msg_success
        self.assertEqual(expected, actual)


if __name__ == '__main__':
    unittest.main()
