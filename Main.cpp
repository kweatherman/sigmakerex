
// Plugin main
#include "SigMaker.h"

// UI "actions"
enum SIG_ACTION
{
	CREATE_FUNCTION_SIG,
	CREATE_ADDRESS_SIG,
	CREATE_RANGE_SIG
};

// Global settings instance
SETTINGS settings;

static void idaapi OnRepoLink(int button_code, form_actions_t& fa) { open_url("https://github.com/kweatherman/sigmakerex"); }
static void idaapi OnOptionButton(int button_code, form_actions_t& fa)
{
    const char optionsDialog[] =
    {
		"SigMakerEx Options\n\n"

		// Output format dropdown
		"<#Signature output style.#Output format:b:0:100:>\n"
        // Mask byte for the inline wildcard style
        "<#Mask/wildcard byte for the \"inline\" BYTE output format.#Mask byte (0xAE default):N:0:4:>\n"

		// Function criteria dropdown
		"<#Function signature generation criteria option.#Function sigs:b:0:100:>\n"

		// Output level dropdown
        "<#IDA output message level.#Message level:b:0:100:>\n"

        "<#Maximum function refs to scan when a function is not unique.#Max function scan refs (0 for unlimited):D:0:4:>\n"
        " \n"
    };

    settings.Validate();

	qstrvec_t outputFormatArray;
    outputFormatArray.push_back("IDA (Default)");
    outputFormatArray.push_back("Code style");
    outputFormatArray.push_back("Inline byte");

	qstrvec_t funcCriteriaArray;
    funcCriteriaArray.push_back("Entry Point (Default)");
    funcCriteriaArray.push_back("Minimal byte size");
    funcCriteriaArray.push_back("Full function body");

	qstrvec_t outputLevelArray;
	outputLevelArray.push_back("Terse (Default)");
	outputLevelArray.push_back("Verbose");

    UINT64 maxRefCount64 = (UINT64) settings.maxScanRefCount;
    ea_t maskByteEa = (ea_t) settings.maskByte;

	int result = ask_form(optionsDialog, &outputFormatArray,&settings.outputFormat, &maskByteEa, &funcCriteriaArray,&settings.funcCriteria, &outputLevelArray,&settings.outputLevel, &maxRefCount64);
	if (result > 0)
	{
        settings.maxScanRefCount = (UINT32) min(maxRefCount64, UINT_MAX);
        settings.maskByte = (BYTE) min(maskByteEa, 0xFF);
		settings.Save();
	}
}

static bool idaapi run(size_t arg)
{
    // To facilitate passing action options via "plugins.cfg" hotkeys
    WORD action = (WORD) arg;

    if (action == 0)
    {
        const char mainDialog[] =
        {
            "BUTTON YES* Continue\n"

            // ---------------- Help ----------------
			"HELP\n"
			"SigMakerEx Plugin:\n"
			"IDA Pro signature creation tool.\n"
            "Copyright\xC2\xA9 2022 Kevin Weatherman. Released under the MIT License.\n"

            "\n"
            "Create signature operations:\n"
			"1. \"Function\": Used to create a unique function entry point, a minimal function signature w/offset, or a whole-body signature depending on the \"Options\" config (see below).\n"
            "First select any address inside the target function.\n"
            "If the selected function is not unique (for the entry point, or the minimal option) then a signature for a unique function cross reference scan will be attempted.\n"
            "Typical use cases: Signatures to locate functions at run time in target memory, to locate functions in IDA after executable updates, or to help locate known libraries by signature, etc.\n\n"

            "2) \"At address\": Attempts to find a unique signature at the selected address.\n"
            "Typical use case: For locating a particular offset at runtime to hook, or making Cheat Engine script signatures for this purpose, etc.\n\n"

            "3. \"From address range\": Generates a signature from the selected address range, not checking for uniqueness.\n"
            "Special use case for when one of the other actions won't work.\n\n"

            "Signature results are pushed to the Windows clipboard for easy CTRL+V pasting into source code, etc.\n"

            "\n"
            "Options: (via the \"Options\" button)\n"
			"Output format:\n"
			"\"IDA\": The default hex binary search format that IDA and some other tools support, using spaced hex bytes and \"??\" wildcards.\n"
			"Example: \"C1 6C E8 ?? ?? ?? ?? 8B 50 08\"\n"
			"\"Code style\": Escape coded hex string and a separate mask string where 'x' are keeper bytes, and '?' are wildcard bytes.\n"
			"Example: \"\\xC1\\x6C\\xE8\\xCC\\xCC\\xCC\\xCC\\x8B\\x50\\x08\", \"xxx????xxx\"\n"
			"\"Inline byte\": A minimalist C style array of bytes with wildcard bytes included format.\n"
			"Example: \"{0xC1,0x6C,0xE8,0xAE,0xAE,0xAE,0xAE,0x8B,0x50,0x08};\"\n"
			"Use the \"mask byte\" edit box to change the default \"Inline byte\" mask byte.\n\n"

			"Function sigs:\n"
			"The criteria for \"Function\" signature generation.\n"
			"\"Entry point\": Will attempt to generate a minimal byte sized function entry point signature when possible.\n"
			"\"Minimal byte size\": Will attempt to generate a minimal, with least wildcards count, byte sized (five are greater) instruction boundary aligned signature inside of the selected function body.\n"
			"\"Full function body\": Will attempt to generate a unique full function body signature.\n\n"

			"For any of these three options, if the function is not unique, an attempt will be made to locate the smallest unique cross reference signature instead.\n"
            "If you wish to make a full or partial function signature for a non-unique function then use the \"From address range\" option instead.\n\n"

			"\"Message level\": Set to \"Verbose\" for internal signature generation message output to the IDA log window.\n\n"

			"\"Max function scan refs\": Limit how many function cross references to search when a direct \"Function\" action signature can't be found.\n"
            "Normally this should be '0' for unlimited search, but for problem cases where there are so many references that causes a slowdown, this can be set to some reasonable limit like 16 or 100.\n\n"

			"For the relatively rare case of functions that have their chunks spread over multiple address ranges, the tool will attempt to use just the first chunk.\n"
            "If wishing to make a signature in one of the disjointed chunks, try using the \"At address\" method. If all else fails, try a \"From address range\" sig (might take some manual searching for uniqueness).\n"

            "\n"
		   "Credits:\n"
            "Thanks to the creator of the original SigMaker tool back from the gamedeception.net days up to the current C/C++ and Python iteration authors.\n"
            "P4TR!CK, bobbysing, xero|hawk, ajkhoury, and zoomgod et al.\n"
            "Thanks to Wojciech Mula for his SIMD programming resources.\n\n"

			"See the SigMakerEx READ.ME for more help and details.\n"
			"ENDHELP\n"
            // --------------------------------------

            // Dialog title
            "SigMakerEx\n\n"

            // Message text
            "SigMakerEx %q \t\n"

            "<#Click to open SigMakerEx repo page.#SigmakerEx Github:k::>\n\n"

            "Create signature:\n"
            "<#Attempt to create a unique function signature for selected address at or inside the function.#Function:R>\n"
            "<#Attempt to create a unique signature at selected address.#At address:R>\n"
            "<#Create a raw signiture for selected adress range, unique or not.#From address range           \t:R>>\n\n"

            "<#Options:B::>\n"
            " \n"
        };

        static WORD lastAction = CREATE_FUNCTION_SIG;
        qstring version, tmp;
        version.sprnt("v%s, built %s.", GetVersionString(MY_VERSION, tmp).c_str(), __DATE__);

        int result = ask_form(mainDialog, &version, OnRepoLink, &lastAction, OnOptionButton);
        if (result <= 0)
            return true;
        else
            action = lastAction;
    }
    else
        action -= 1;

    switch ((SIG_ACTION) action)
    {
        // Attempt to create an ideal function signature
		case CREATE_FUNCTION_SIG:
        CreateFunctionSig();
        break;

        // Attempt to create a signature for a selected address
		case CREATE_ADDRESS_SIG:
        CreateAddressSig();
		break;

        // Create a raw signature for a selected address range, unique or not
		case CREATE_RANGE_SIG:
        CreateAddressRangeSig();
		break;
    };
    return true;
}

static plugmod_t* idaapi init()
{
    settings.Load();
    return PLUGIN_OK;
}

void idaapi term()
{
    SearchCleanup();
}

__declspec(dllexport) plugin_t PLUGIN =
{
    IDP_INTERFACE_VERSION,
    PLUGIN_PROC,
    init,
    term,
    run,
    "Signature creation tool.",
    "SigMakerEx plugin",
    "SigMakerEx",
    "Ctrl-Alt-S"
};
