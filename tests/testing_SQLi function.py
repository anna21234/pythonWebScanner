import unittest
import pythonScannerCMD

testing_url = "http://192.168.59.128/dvwa/vulnerabilities/sqli/"

returned_msg_success = "A possible SQLi has been found here: " + testing_url
returned_msg_fail = "Sorry, no SQLis have been found at this url address "
returned_form_msg_success = "A possible SQLi has been found in this form: " + testing_url
returned_form_msg_fail = "Sorry, no SQLis have been found in this form"


class SQLiTestCase(unittest.TestCase):
    def test_sqli_success(self):
        actual = pythonScannerCMD.scan_for_sqli(testing_url)

        expected = returned_msg_fail + " " + returned_form_msg_success

        self.assertEqual(expected, actual)

    def test_sqli_form(self):
        actual = pythonScannerCMD.scan_for_sqli(testing_url)
        expected = returned_msg_fail, returned_form_msg_success
        self.assertEqual(expected, actual)


if __name__ == '__main__':
    unittest.main()
