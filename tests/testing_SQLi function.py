import unittest
import pythonScannerCMD

testing_url = "http://172.16.218.131/dvwa/vulnerabilities/sqli/"
url_testing_form = " Here is the vulnerable form: {'action': '#', 'method': 'get', 'inputs': [{'type': 'text', 'name': 'id', 'value': ''}, {'type': 'submit', 'name': 'Submit', 'value': 'Submit'}]} "

returned_msg_success = "A possible SQLi has been found here: " + testing_url
returned_msg_fail = "Sorry, there are no SQLis at this url address."
returned_form_msg_success = " A possible SQLi has been found in this form: " + testing_url + " \n" + url_testing_form
returned_form_msg_fail = "Sorry, no SQLis have been found in this form"




class SQLiTestCase(unittest.TestCase):
    def test_sqli_success(self):
        actual = pythonScannerCMD.scan_for_sqli(testing_url)

        expected = returned_msg_fail + returned_form_msg_success

        self.assertEqual(expected, actual)

    def test_sqli_form(self):
        actual = pythonScannerCMD.scan_for_sqli(testing_url)
        expected = returned_msg_fail, returned_form_msg_success
        self.assertEqual(expected, actual)


if __name__ == '__main__':
    unittest.main()
