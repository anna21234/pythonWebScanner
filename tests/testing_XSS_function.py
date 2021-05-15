import unittest
import pythonScannerCMD

testing_url = "http://192.168.59.128/dvwa/vulnerabilities/xss_r/"
returned_form_msg_success = f"Found XSS at this address: {testing_url}"
returned_form_msg_fail = "Sorry, no XSS was found"
class XSSTestCase(unittest.TestCase):
    def test_XSS(self):
        actual = pythonScannerCMD.scan_for_xss(testing_url)
        expected = returned_form_msg_success
        self.assertEqual(expected, actual)


if __name__ == '__main__':
    unittest.main()
