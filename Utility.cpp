
// IDA plugin utility support
#include "StdAfx.h"
#include <tchar.h>
#include <winnt.h>

static ALIGN(16) TIMESTAMP performanceFrequency = 0;
struct OnUtilityInit
{
	OnUtilityInit()
	{
		LARGE_INTEGER large;
		QueryPerformanceFrequency(&large);
		performanceFrequency = (TIMESTAMP) large.QuadPart;
	}
} static _utilityInit;

qstring &GetVersionString(UINT32 version, qstring &version_string)
{
	version_string.sprnt("%u.%u.%u", GET_VERSION_MAJOR(MY_VERSION), GET_VERSION_MINOR(MY_VERSION), GET_VERSION_PATCH(MY_VERSION));
	VERSION_STAGE stage = GET_VERSION_STAGE(version);
	switch (GET_VERSION_STAGE(version))
	{
		case VERSION_ALPHA:	version_string += "-alpha";	break;
		case VERSION_BETA: version_string += "-beta"; break;
	};
	return version_string;
}

// Return high resolution floating elapsed seconds
TIMESTAMP GetTimestamp()
{
	LARGE_INTEGER large;
	QueryPerformanceCounter(&large);
	return ((TIMESTAMP) large.QuadPart / performanceFrequency);
}


LPCSTR TimestampString(TIMESTAMP time, __out_bcount_z(64) LPSTR buffer)
{
	if(time >= HOUR)
		sprintf_s(buffer, 64, "%.2f hours", (time / (TIMESTAMP) HOUR));
	else
	if(time >= MINUTE)
		sprintf_s(buffer, 64, "%.2f minutes", (time / (TIMESTAMP) MINUTE));
	else
	if(time < (TIMESTAMP) 0.01)
		sprintf_s(buffer, 64, "%.2f ms", (time * (TIMESTAMP) 1000.0));
	else
		sprintf_s(buffer, 64, "%.2f seconds", time);
	return buffer;
}

LPSTR NumberCommaString(UINT64 n, __out_bcount_z(32) LPSTR buffer)
{
	int i = 0, c = 0;
	do
	{
		buffer[i] = ('0' + (n % 10)); i++;

		n /= 10;
		if ((c += (3 && n)) >= 3)
		{
			buffer[i] = ','; i++;
			c = 0;
		}

	} while (n);
	buffer[i] = 0;
	return _strrev(buffer);
}

// Send text to the Windows clipboard for pasting
BOOL SetClipboard(LPCSTR text)
{
	BOOL result = false;

	if (OpenClipboard(NULL))
	{
		if (EmptyClipboard())
		{
			size_t dataSize = (strlen(text) + 1);
			if (dataSize > 1)
			{
				HGLOBAL memHandle = GlobalAlloc(GMEM_MOVEABLE, dataSize);
				if (memHandle)
				{
					LPSTR textMem = (LPSTR) GlobalLock(memHandle);
					if (textMem)
					{
						memcpy(textMem, text, dataSize);
						GlobalUnlock(memHandle);
						result = (SetClipboardData(CF_TEXT, memHandle) != NULL);
					}
				}
			}
		}

		CloseClipboard();
	}

	return result;
}

// Get line of disassembled code text sans color tags
void GetDisasmText(ea_t ea, __out qstring &s)
{
	s.clear();
	generate_disasm_line(&s, ea, (GENDSM_FORCE_CODE | GENDSM_REMOVE_TAGS | GENDSM_MULTI_LINE));
}


// ================================================================================================
// IDA flag dumping utility

// Duplicated from IDA SDK "bytes.hpp" since using these directly makes the code possible or just simpler
// * Type
#define FF_CODE 0x00000600LU	// Code
#define FF_DATA 0x00000400LU    // Data
#define FF_TAIL 0x00000200LU    // Tail; second, third (tail) byte of instruction or data
#define FF_UNK  0x00000000LU    // Unexplored

// * Data F0000000
#define DT_TYPE		0xF0000000	// Data type mask
#define FF_BYTE     0x00000000	// byte
#define FF_WORD     0x10000000	// word
#define FF_DWORD    0x20000000  // double word
#define FF_QWORD    0x30000000  // quad word
#define FF_TBYTE    0x40000000  // triple byte
#define FF_STRLIT   0x50000000  // string literal
#define FF_STRUCT   0x60000000  // struct variable
#define FF_OWORD    0x70000000  // octal word/XMM word (16 bytes/128 bits)
#define FF_FLOAT    0x80000000  // float
#define FF_DOUBLE   0x90000000  // double
#define FF_PACKREAL 0xA0000000  // packed decimal real
#define FF_ALIGN    0xB0000000  // alignment directive
//                  0xC0000000  // reserved
#define FF_CUSTOM   0xD0000000  // custom data type
#define FF_YWORD    0xE0000000  // YMM word (32 bytes/256 bits)
#define FF_ZWORD    0xF0000000  // ZMM word (64 bytes/512 bits)

// * Code F0000000
#define MS_CODE 0xF0000000LU	// Code type mask
#define FF_FUNC 0x10000000LU	// Function start
//              0x20000000LU    // Reserved
#define FF_IMMD 0x40000000LU    // Has Immediate value
#define FF_JUMP 0x80000000LU    // Has jump table or switch_info

// * Instruction/Data operands 0F000000
#define MS_1TYPE 0x0F000000LU   // Mask for the type of other operands
#define FF_1VOID 0x00000000LU   // Void (unknown)
#define FF_1NUMH 0x01000000LU   // Hexadecimal number
#define FF_1NUMD 0x02000000LU   // Decimal number
#define FF_1CHAR 0x03000000LU   // Char ('x')
#define FF_1SEG  0x04000000LU   // Segment
#define FF_1OFF  0x05000000LU   // Offset
#define FF_1NUMB 0x06000000LU   // Binary number
#define FF_1NUMO 0x07000000LU   // Octal number
#define FF_1ENUM 0x08000000LU   // Enumeration
#define FF_1FOP  0x09000000LU   // Forced operand
#define FF_1STRO 0x0A000000LU   // Struct offset
#define FF_1STK  0x0B000000LU   // Stack variable
#define FF_1FLT  0x0C000000LU   // Floating point number
#define FF_1CUST 0x0D000000LU   // Custom representation

#define MS_0TYPE 0x00F00000LU	// Mask for 1st arg typing
#define FF_0VOID 0x00000000LU   // Void (unknown)
#define FF_0NUMH 0x00100000LU   // Hexadecimal number
#define FF_0NUMD 0x00200000LU   // Decimal number
#define FF_0CHAR 0x00300000LU   // Char ('x')
#define FF_0SEG  0x00400000LU   // Segment
#define FF_0OFF  0x00500000LU   // Offset
#define FF_0NUMB 0x00600000LU   // Binary number
#define FF_0NUMO 0x00700000LU   // Octal number
#define FF_0ENUM 0x00800000LU   // Enumeration
#define FF_0FOP  0x00900000LU   // Forced operand
#define FF_0STRO 0x00A00000LU   // Struct offset
#define FF_0STK  0x00B00000LU   // Stack variable
#define FF_0FLT  0x00C00000LU   // Floating point number
#define FF_0CUST 0x00D00000LU   // Custom representation

// * State information 000FF800
#define MS_COMM   0x000FF800    // Mask of common bits
#define FF_FLOW   0x00010000    // Exec flow from prev instruction
#define FF_SIGN   0x00020000    // Inverted sign of operands
#define FF_BNOT   0x00040000    // Bitwise negation of operands
#define FF_UNUSED 0x00080000    // unused bit (was used for variable bytes)
#define FF_COMM   0x00000800    // Has comment
#define FF_REF    0x00001000    // has references
#define FF_LINE   0x00002000    // Has next or prev lines
#define FF_NAME   0x00004000    // Has name
#define FF_LABL   0x00008000    // Has dummy name
// 000001FF
#define FF_IVL  0x00000100LU	// Has byte value in 000000FF

// Decode IDA address flags value into a readable string
void IdaFlags2String(flags_t f, __out qstring &s, BOOL withValue)
{
	s.clear();
    #define FTEST(_f) if(f & _f){ if(!first) s += ", "; s += #_f; first = FALSE; }

	// F0000000
	BOOL first = TRUE;
	if(is_data(f))
	{
		switch(f & DT_TYPE)
		{
			case FF_BYTE    : s += "FF_BYTE";     break;
			case FF_WORD    : s += "FF_WORD";     break;
			case FF_DWORD	: s += "FF_DWORD";    break;
			case FF_QWORD	: s += "FF_QWORD";    break;
			case FF_TBYTE	: s += "FF_TBYTE";    break;
			case FF_STRLIT	: s += "FF_STRLIT";   break;
			case FF_STRUCT  : s += "FF_STRUCT";   break;
			case FF_OWORD	: s += "FF_OWORD";    break;
			case FF_FLOAT   : s += "FF_FLOAT";	  break;
			case FF_DOUBLE  : s += "FF_DOUBLE";   break;
			case FF_PACKREAL: s += "FF_PACKREAL"; break;
			case FF_ALIGN   : s += "FF_ALIGN";    break;

			case FF_CUSTOM	: s += "FF_CUSTOM";   break;
			case FF_YWORD	: s += "FF_YWORD";    break;
			case FF_ZWORD	: s += "FF_ZWORD";    break;

		};
		first = FALSE;
	}
	else
	if(is_code(f))
	{
		if(f & MS_CODE)
		{
			FTEST(FF_FUNC);
			FTEST(FF_IMMD);
			FTEST(FF_JUMP);
		}
	}

	// 0F000000
	if(f & MS_1TYPE)
	{
		if(!first) s += ", ";
		switch(f & MS_1TYPE)
		{
			//default: s += ",FF_1VOID"; break;
			case FF_1NUMH: s += "FF_1NUMH"; break;
			case FF_1NUMD: s += "FF_1NUMD"; break;
			case FF_1CHAR: s += "FF_1CHAR"; break;
			case FF_1SEG:  s += "FF_1SEG";  break;
			case FF_1OFF:  s += "FF_1OFF";  break;
			case FF_1NUMB: s += "FF_1NUMB"; break;
			case FF_1NUMO: s += "FF_1NUMO"; break;
			case FF_1ENUM: s += "FF_1ENUM"; break;
			case FF_1FOP:  s += "FF_1FOP";  break;
			case FF_1STRO: s += "FF_1STRO"; break;
			case FF_1STK:  s += "FF_1STK";  break;
			case FF_1FLT:  s += "FF_1FLT";  break;
			case FF_1CUST: s += "FF_1CUST"; break;
		};
		first = FALSE;
	}

	// 00F00000
	if(f & MS_0TYPE)
	{
		if(!first) s += ", ";
		switch(f & MS_0TYPE)
		{
			//default: s += ",FF_0VOID"; break;
			case FF_0NUMH: s += "FF_0NUMH"; break;
			case FF_0NUMD: s += "FF_0NUMD"; break;
			case FF_0CHAR: s += "FF_0CHAR"; break;
			case FF_0SEG : s += "FF_0SEG";  break;
			case FF_0OFF : s += "FF_0OFF";  break;
			case FF_0NUMB: s += "FF_0NUMB"; break;
			case FF_0NUMO: s += "FF_0NUMO"; break;
			case FF_0ENUM: s += "FF_0ENUM"; break;
			case FF_0FOP : s += "FF_0FOP";  break;
			case FF_0STRO: s += "FF_0STRO"; break;
			case FF_0STK : s += "FF_0STK";  break;
			case FF_0FLT : s += "FF_0FLT";  break;
			case FF_0CUST: s += "FF_0CUST"; break;
		};
		first = FALSE;
	}

	// 000F0000
	if(f & 0xF0000)
	{
		FTEST(FF_FLOW);
		FTEST(FF_SIGN);
		FTEST(FF_BNOT);
		FTEST(FF_UNUSED);
	}

	// 0000F000
	if(f & 0xF000)
	{
		FTEST(FF_REF);
		FTEST(FF_LINE);
		FTEST(FF_NAME);
		FTEST(FF_LABL);
	}

	// 00000F00
	if(!first) s += ", ";
	switch(f & (FF_CODE | FF_DATA | FF_TAIL))
	{
		case FF_CODE: s += "FF_CODE"; break;
		case FF_DATA: s += "FF_DATA"; break;
		case FF_TAIL: s += "FF_TAIL"; break;
		default: s += "FF_UNK";	   break;
	};
	first = FALSE;
	if(f & FF_COMM) s += ", FF_COMM";
	if(f & FF_IVL)  s += ", FF_IVL";

	// 000000FF optional value dump
    if (withValue && (f & FF_IVL))
	{
        char buffer[16];
        sprintf_s(buffer, sizeof(buffer), ", value: %02X", (f & 0xFF));
		s += buffer;
	}

	#undef FTEST
}

// Dump flags at address w/optional byte value dump
void DumpFlags(ea_t ea, BOOL withValue)
{
    qstring s;
    IdaFlags2String(get_flags(ea), s, withValue);
    msg(EAFORMAT " Flags: %s\n", ea, s.c_str());
}


// ------------------------------------------------------------------------------------------------

// Print C SEH information
int ReportException(LPCSTR name, LPEXCEPTION_POINTERS nfo)
{
	msg(MSG_TAG "** Exception: 0x%08X @ 0x%llX, in %s()! **\n", nfo->ExceptionRecord->ExceptionCode, nfo->ExceptionRecord->ExceptionAddress, name);
	return EXCEPTION_EXECUTE_HANDLER;
}
