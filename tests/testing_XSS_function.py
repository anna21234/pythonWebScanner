import unittest
import pythonScannerCMD

testing_url = "http://172.16.218.131/dvwa/vulnerabilities/xss_r/"
url_testing_form = """Here is the vulnerable form
 {'action': '#', 'method': 'get', 'inputs': [{'type': 'text', 'name': 'name', 'value': "<sCriPt>alert('Testing for XSS')</ScriPt>"}, {'type': 'submit', 'name': None, 'value': 'Submit'}]} """
returned_form_msg_success = f"Found XSS at this address: {testing_url}\n\n" + url_testing_form
returned_form_msg_fail = "Sorry, no XSS was found"
class XSSTestCase(unittest.TestCase):
    def test_XSS(self):
        actual = pythonScannerCMD.scan_for_xss(testing_url)
        expected = returned_form_msg_success
        self.assertEqual(expected, actual)


if __name__ == '__main__':
    unittest.main()
