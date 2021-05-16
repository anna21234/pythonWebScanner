import PySimpleGUI as Gui
import pythonScannerCMD


# The gui for this application is done using the PySimpleGUI module.
# This is a free template from the PySimpleGUI site
# that I modified so that I can have multiple windows at one time.
# This is so multiple pages can be scanned and shown in the report page
# instead of restarting the application over and over again.
def main_window_layout():
    # This is the main window where you input the testing URL address
    layout = [
        [Gui.Text("Enter the address you want to scan")
         ],
        [Gui.Input(key='-TARGET-', enable_events=True)],
        [Gui.Text(size=(60, 2), key='-SCAN-')],
        [Gui.Button('Ok'), Gui.Button('Report'), Gui.Button('Exit')]]
    return Gui.Window('Web Application Scanner', layout, location=(400, 300), finalize=True)


def report_window_layout():
    # This is the report window, where the scan results will show up.
    layout = [
        [Gui.Text(""), Gui.Text(size=(80, 30), key='-REPORT-')
         ],

        [Gui.Button('Exit')]]
    return Gui.Window('Scanner Report', layout, location=(400, 300), finalize=True)


# The windows are initialised here
scan_window, report_window = main_window_layout(), None

# This is the main loop where the windows are read, modified and so on
while True:
    window, event, values = Gui.read_all_windows()
    
    # If the user clicks the Exit button or closes the window via the X button, close the window
    if event == Gui.WINDOW_CLOSED or event == 'Exit':
        window.close()
        if window == report_window:  # Check which window is being closed.
            # If its window 2 (the report window) close it but keep 1 open
            report_window = None
        elif window == scan_window:  # If the window being closed is the main window (the scan window)
            # close the app itself
            break
    if event == 'Report' and not report_window:
        report_window = report_window_layout()
        print(scan_window)
        # Here the output from the main scanner functions is displayed in the report window
        if (values['-TARGET-']) is "":
            report_window['-REPORT-'].update("You haven't scanned a target yet. Enter an address and click Ok")
        elif (values['-TARGET-']) is not "":

            report_window['-REPORT-'].update(
                    scan_result_sql + "\n " + "\n " + scan_result_xss + "\n " + "\n " + scan_result_lfi + "\n " + "\n " + scan_result_rfi)

    if event == 'Ok':
        scan_result_sql = ""
        scan_result_xss = ""
        scan_result_lfi = ""
        scan_result_rfi = ""
        # This event grab the URL input from the main window (window 1) and sends it to the scanner modules
        # The results of each scanner function is stored in a variable
        # which is used above to be able to display the contents
        if (values['-TARGET-']) is "":
            scan_window['-SCAN-'].update("You haven't scanned a target yet. Enter an address and click Ok")
        elif (values['-TARGET-']) is not "":
            address_to_scan = (values['-TARGET-'])
            scan_result_sql = pythonScannerCMD.scan_for_sqli(address_to_scan)
            scan_result_xss = pythonScannerCMD.scan_for_xss(address_to_scan)
            scan_result_lfi = pythonScannerCMD.scan_for_lfi(address_to_scan)
            scan_result_rfi = pythonScannerCMD.scan_for_rfi(address_to_scan)






window.close()
