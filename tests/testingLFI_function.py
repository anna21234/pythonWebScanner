import unittest
import pythonScannerCMD

testing_url = "http://172.16.218.131/dvwa/vulnerabilities/fi/?page=index.php"
found_testing_url = "http://172.16.218.131/dvwa/vulnerabilities/fi/?page=/etc/passwd"
found_address = "Address: " + found_testing_url
returned_msg_success = "It worked! The file was found!" + " \n " + found_address

returned_msg_fail = "Sorry, no file inclusion found"


class LFITestCase(unittest.TestCase):
    def test_local_file_inclusion(self):
        actual = pythonScannerCMD.scan_for_lfi(testing_url)
        expected = returned_msg_success
        self.assertEqual(expected, actual)


if __name__ == '__main__':
    unittest.main()
