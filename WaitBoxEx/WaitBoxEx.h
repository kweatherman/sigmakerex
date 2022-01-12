
// WaitBoxEx: Custom IDA Pro wait box
// By Sirmabus
// Version 1.6
// http://www.macromonkey.com
// License: Qt LGPL
#pragma once

// Define MATERIAL_DESIGN_STYLE for a "material design" inspired style
#ifndef _LIB
	#ifndef MATERIAL_DESIGN_STYLE
		#ifndef __EA64__
			#ifndef _DEBUG
			#pragma comment(lib, "WaitBoxEx.LiB")
			#else
			#pragma comment(lib, "WaitBoxExD.LiB")
			#endif
		#else
			#ifndef _DEBUG
			#pragma comment(lib, "WaitBoxEx64.LiB")
			#else
			#pragma comment(lib, "WaitBoxExD64.LiB")
			#endif
		#endif
	#else
		#ifndef __EA64__
			#ifndef _DEBUG
			#pragma comment(lib, "WaitBoxExMd.LiB")
			#else
			#pragma comment(lib, "WaitBoxExMdD.LiB")
			#endif
		#else
			#ifndef _DEBUG
			#pragma comment(lib, "WaitBoxExMd64.LiB")
			#else
			#pragma comment(lib, "WaitBoxExMdD64.LiB")
			#endif
		#endif
	#endif // MATERIAL_DESIGN_STYLE
#endif // _LIB

namespace WaitBox
{
    // Show the modal wait box dialog
    void show(LPCSTR titleText = "Progress", LPCSTR labelText = "Please wait..", LPCSTR styleSheet = NULL, LPCSTR icon = NULL);

    // Stop the wait box
    void hide();

    // Check if user canceled and optionally the update progress too w/built-in timed update limiter.
    // Progress range: 0 to 100, or -1 to switch to indeterminate mode.
    BOOL updateAndCancelCheck(int progress = 0);


    // Returns TRUE if ready for internal update
    BOOL isUpdateTime();

    // Returns TRUE if wait box up
    BOOL isShowing();

    // Change the label text
    void setLabelText(LPCSTR labelText);

    // Convenience wrapper of Qt function "QApplication::processEvents();" to tick IDA's Qt event queue
    void processIdaEvents();
};


