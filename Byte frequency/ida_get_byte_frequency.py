
"""
IDA Pro script to gather byte frequency table for code sections in the loaded IDB
saving the data to a JSON file.
"""
import json
import ctypes
from pprint import pprint
from idaapi import *
import ida_kernwin as kernwin

# Import: void QCoreApplication::processEvents(QEventLoop::ProcessEventsFlag = AllEvents)
# https://doc.qt.io/qt-5/qcoreapplication.html#processEvents
processEventsPtr = None
if kernwin.is_idaq():
    # If IDA Windows
    if os.name == 'nt':
        qtcore = ctypes.CDLL('Qt5Core')
        if qtcore:
            processEventsPtr = qtcore['?processEvents@QCoreApplication@QT@@SAXV?$QFlags@W4ProcessEventsFlag@QEventLoop@QT@@@2@@Z']

# Call QT processEvents() to trigger the IDA output window to update immediately
def refresh():
    if processEventsPtr:
        processEventsPtr(ctypes.c_uint(0))


# Ask user for save file name
save_path = ask_file(True, "*.json", "Script: Select the byte frequency JSON save file:")
if save_path:
    frequency = {}

    # Walk all code segments..
    for n in range(get_segm_qty()):
        seg = getnseg(n)
        if seg.type == SEG_CODE:
            print(f'Script: Walking: "{get_segm_name(seg)}" {seg.start_ea:014X} - {seg.end_ea:014X}')
            refresh()

            # Add all code bytes..
            ea = seg.start_ea
            while ea < seg.end_ea:
                # For bytes that don't exist in the IDB for a given address this get_db_byte() return 0xFF
                byte = get_db_byte(ea)
                frequency[byte] = frequency.get(byte, 0) + 1
                ea += 1

    #pprint(frequency)

    # Save the byte frequency table
    print(f'Script: Saving to "{save_path}"..')
    refresh()
    with open(save_path, "w") as fp:
        json.dump(frequency, fp, indent=2)
    print("Script: Done.")
else:
    print("Script: Aborted.")
refresh()
