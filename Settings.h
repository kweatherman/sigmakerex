
#pragma once

// Settings container
struct SETTINGS
{
	#define SETTINGS_FILENAME "SigMakerEx.cfg"

	// Function signature creation criteria
	enum FUNC_CRITERIA
	{
		FUNC_ENTRY_POINT,	// Function entry point
		FUNC_MIN_SIZE,		// By minimal byte size
		FUNC_FULL,			// Sig of all function instructions (just first section, if has multiple)
	};
	FUNC_CRITERIA funcCriteria;

	enum OUTPUT_FORMAT: int
	{
		OF_IDA,		// IDA and others "AB 78 E8 ?? ?? ?? ?? CC" style spaced bytes with wildcards
		OF_CODE,	// Escape encoded binary with ASCII mask "code" style in two strings.
					// E.g. "\x33\x9A\xFA\x00\x00\x00\x00\x45\x68", "xxxxxxx????xx"
		OF_INLINE,	// Like "code" style, but byte string with inlined bytes w/wildcard
					// E.g. "{0x33,0x9A,0xFA,0xAE,0xAE,0xAE,0xAE,0x45,0x68}", where 0xAE is the wildcard bytes.
	};
	OUTPUT_FORMAT outputFormat;

	// IDA message output log level
	enum OUTPUTLEVEL: int
	{
		LL_TERSE,    // Minimal/normal output
		LL_VERBOSE   // Verbose for monitoring and troubleshooting
	};
	OUTPUTLEVEL outputLevel;

	// Maximum code reference search candidates
	// 0 = unlimited
	UINT32 maxScanRefCount;

	// Byte mask/wildcard byte for the "inline" output format
	BYTE maskByte;

	SETTINGS()
	{
		funcCriteria = SETTINGS::FUNC_ENTRY_POINT;
		outputFormat = SETTINGS::OF_IDA;
		outputLevel = SETTINGS::LL_TERSE;
		maxScanRefCount = 0;
		maskByte = 0xAE; // Default, one of the least common code byte frequency values
	};

	void Validate()
	{
		CLAMP(funcCriteria, SETTINGS::FUNC_ENTRY_POINT, SETTINGS::FUNC_FULL);
		CLAMP(outputFormat, SETTINGS::OF_IDA, SETTINGS::OF_INLINE);
		CLAMP(outputLevel, SETTINGS::LL_TERSE, SETTINGS::LL_VERBOSE);
	}

	void Save()
	{
		char path[MAXSTR];
		qsnprintf(path, MAXSTR - 1, "%s\\%s", get_user_idadir(), SETTINGS_FILENAME);
		FILE* fp = qfopen(path, "wb");
		if (fp)
		{
			Validate();
			qfwrite(fp, this, sizeof(SETTINGS));
			qfclose(fp);
		}
	}

	void Load()
	{
		char path[MAXSTR];
		qsnprintf(path, MAXSTR - 1, "%s\\%s", get_user_idadir(), SETTINGS_FILENAME);
		FILE* fp = qfopen(path, "rb");
		if (fp)
		{
			qfread(fp, this, sizeof(SETTINGS));
			qfclose(fp);
			Validate();
		}
	}
};

// Global instance
extern SETTINGS settings;

#define LOG_TERSE(...) { if (settings.outputLevel >= SETTINGS::LL_TERSE) msg(__VA_ARGS__); }
#define LOG_VERBOSE(...) { if (settings.outputLevel >= SETTINGS::LL_VERBOSE) msg(__VA_ARGS__); }
