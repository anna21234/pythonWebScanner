# sample gui for project
# the gui is fully working now
import PySimpleGUI as gui
import pythonScannerCMD


def the_window1():
    layout = [
        [gui.Text("Enter the host you want to scan")
         ],
        [gui.Input(key='-IN-', enable_events=True)],
        [gui.Text(size=(60, 2), key='-OUT-')],
        [gui.Button('Ok'), gui.Button('Report'), gui.Button('Exit')]]
    return gui.Window('Web Application Scanner', layout, location=(400, 300), finalize=True)


def the_window2():
    layout = [
        [gui.Text(""), gui.Text(size=(80, 30), key='-OUTPUT-')
         ],

        [gui.Button('Exit')]]
    return gui.Window('Scanner Report', layout, location=(400, 300), finalize=True)


# Create the window
window1, window2 = the_window1(), None

# Create an event loop
while True:
    window, event, values = gui.read_all_windows()

    # See if user wants to quit or window was closed
    if event == gui.WIN_CLOSED or event == 'Exit':
        window.close()
        if window == window2:  # if closing win 2, mark as closed
            window2 = None
        elif window == window1:  # if closing win 1, exit program
            break
    elif event == 'Report' and not window2:
        window2 = the_window2()
        # gui.easy_print("Hello this is the report")
        # gui.easy_print(scan_result_sql)
        # gui.easy_print(scan_result_xss)
        # gui.easy_print(scan_result_lfi)
        # gui.easy_print(scan_result_rfi)
        window2['-OUTPUT-'].update(scan_result_sql + "\n " + "\n " + scan_result_xss + "\n " + "\n " + scan_result_lfi + "\n " + "\n " + scan_result_rfi)

    if event == 'Ok':
        input_url = (values['-IN-'])
        scan_result_sql = pythonScannerCMD.scan_for_sqli(input_url)
        scan_result_xss = pythonScannerCMD.scan_for_xss(input_url)
        scan_result_lfi = pythonScannerCMD.scan_for_lfi(input_url)
        scan_result_rfi = pythonScannerCMD.scan_for_rfi(input_url)
        print(scan_result_lfi)

window.close()
