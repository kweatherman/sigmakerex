
// IDA plugin utility support
#pragma once

// ------------------------------------------------------------------------------------------------

#ifndef __EA64__
#define EAFORMAT "%08X"
#else
#define EAFORMAT "%014llX"
#endif

// Size of string sans terminator
#define SIZESTR(x) (_countof(x) - 1)

#define ALIGN(_x_) __declspec(align(_x_))

#define STACKALIGN(type, name) \
	BYTE space_##name[sizeof(type) + (16-1)]; \
	type &name = *reinterpret_cast<type *>((UINT_PTR) (space_##name + (16-1)) & ~(16-1))

// Now you can use the #pragma message to add the location of the message:
// Examples:
// #pragma message(__LOC__ "important part to be changed")
// #pragma message(__LOC2__ "error C9901: wish that error would exist")
#define __STR2__(x) #x
#define __STR1__(x) __STR2__(x)
#define __LOC__ __FILE__ "("__STR1__(__LINE__)") : Warning MSG: "
#define __LOC2__ __FILE__ "("__STR1__(__LINE__)") : "

template <class T> void CLAMP(T &x, T min, T max) { if (x < min) x = min; else if (x > max) x = max; }

// Semantic versioning for storage 32bit UINT32, using 10 bits (0 to 1023) for major, minor, and patch numbers
// Then 2 bits to (for up to 4 states) to indicate alpha, beta, etc.
// https://semver.org/
enum VERSION_STAGE
{
	VERSION_RELEASE,
	VERSION_ALPHA,
	VERSION_BETA
};
#define MAKE_SEMANTIC_VERSION(_stage, _major, _minor, _patch) ((((UINT32)(_stage) & 3) << 30) | (((UINT32)(_major) & 0x3FF) << 20) | (((UINT32)(_minor) & 0x3FF) << 10) | ((UINT32)(_patch) & 0x3FF))
#define GET_VERSION_STAGE(_version) ((VERSION_STAGE)(((UINT32) (_version)) >> 30))
#define GET_VERSION_MAJOR(_version) ((((UINT32) (_version)) >> 20) & 0x3FF)
#define GET_VERSION_MINOR(_version) ((((UINT32) (_version)) >> 10) & 0x3FF)
#define GET_VERSION_PATCH(_version) (((UINT32) (_version)) & 0x3FF)

qstring &GetVersionString(UINT32 version, qstring& version_string);

// ------------------------------------------------------------------------------------------------

typedef double TIMESTAMP;
#define SECOND 1
#define MINUTE (60 * SECOND)
#define HOUR   (60 * MINUTE)

TIMESTAMP GetTimestamp();

// ------------------------------------------------------------------------------------------------

LPCSTR TimestampString(TIMESTAMP time, __out_bcount_z(64) LPSTR buffer);
LPSTR NumberCommaString(UINT64 n, __out_bcount_z(32) LPSTR buffer);
BOOL SetClipboard(LPCSTR text);
void GetDisasmText(ea_t ea, __out qstring &s);

void IdaFlags2String(flags_t f, __out qstring& s, BOOL withValue = FALSE);
void DumpFlags(ea_t ea, BOOL withValue = FALSE);

// ------------------------------------------------------------------------------------------------

// Note: Build requires "Code Generation" -> "Enable C++ Exceptions" -> "Yes with SEH Exceptions (/EHa)" 
// to enable SEH exceptions - along with the default C++ type.
int ReportException(LPCSTR name, LPEXCEPTION_POINTERS nfo);
#define EXCEPT() __except(ReportException(__FUNCTION__, GetExceptionInformation())){}
#define CATCH() catch (...) { msg(MSG_TAG "** Exception in %s()! ***\n", __FUNCTION__); }
