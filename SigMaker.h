
// Common and shared
#pragma once

#include "StdAfx.h"
#include <vector>

#include "Settings.h"

// Minimal signature byte length
static const UINT32 MIN_SIG_SIZE = 5;

// Signature container
struct SIG
{
    std::vector<BYTE> bytes;
    std::vector<BYTE> mask;	// 0xFF = keep, 0 = wildcard/skip

    // ------------------------------------------------------------------------

	// Append one or more bytes at address to the signature
	void AddBytes(ea_t ea, UINT32 size)
	{
		size_t len = bytes.size();
		bytes.resize(len + size);
		mask.resize(len + size);

		PBYTE bytesPtr = &bytes[len];
		PBYTE maskPtr  = &mask[len];

        // get_db_byte() loop faster than get_bytes(), etc.
		while (size--)
		{
			*bytesPtr = get_db_byte(ea);
			*maskPtr = 0xFF;
			ea++, bytesPtr++, maskPtr++;
		};
	}

	// Append one or more wildcards to a signature
	void AddWildcards(UINT32 size)
	{
		size_t len = bytes.size();
		bytes.resize(len + size);
		mask.resize(len + size);

		PBYTE bytesPtr = &bytes[len];
		PBYTE maskPtr = &mask[len];

		while (size--)
		{
			*bytesPtr++ = 0xCC;
			*maskPtr++ = 0;
		};
	}

    // ------------------------------------------------------------------------

    // Output the sig as a "F8 66 4B ?? ?? ?? 88" format string or "F8 66 4B ? ? ? 88"
    void ToIdaString(__out qstring &string, bool singleByteWildCard) const
    {
        size_t count = bytes.size();
        if (count > 0)
        {
			if (singleByteWildCard)
			{
				string.reserve(count * SIZESTR("? "));
				for (size_t i = 0; i < count; i++)
				{
					if (mask[i])
						string.cat_sprnt("%02X ", bytes[i]);
					else
						string.cat_sprnt("? ");
				}

				// Remove the final ' ' space
				string.remove_last();

			}
			else
			{
				string.reserve(count * SIZESTR("?? "));
				for (size_t i = 0; i < count; i++)
				{
					if (mask[i])
						string.cat_sprnt("%02X ", bytes[i]);
					else
						string.cat_sprnt("?? ");
				}

				// Remove the final ' ' space
				string.remove_last();
			}
        }
    }

    // Convert mask to a "code" style mask string; "xxxxxxx????xxx"
    void ToMaskString(__out qstring &maskStr) const
    {
		int count = (int) mask.size();
        maskStr.resize(count + 1);
		for (int i = 0; i < count; i++)
		{
			if (mask[i])
                maskStr[i] = 'x';
			else
                maskStr[i] = '?';
		}
    }

    // Convert byte pattern to '\x' "code" style encoding; "\x45\xAA\xCC\xCC\xCC\x9A\xFA"
	void ToCodeString(__out qstring &string) const
	{
		size_t count = bytes.size();
		if (count > 0)
		{
			string.reserve(count * SIZESTR("\\xCC"));
			for (size_t i = 0; i < count; i++)
			{
                if (mask[i])
                    string.cat_sprnt("\\x%02X", bytes[i]);
                else
					string += "\\xCC";
			}
		}
	}

	// Convert signature to a "inline" byte style C string. E.g. "{0x33,0x9A,0xFA,0xAE,0xAE,0xAE,0xAE,0x45,0x68}"
	void ToInlineString(__out qstring &string) const
	{
		size_t count = bytes.size();
		if (count > 0)
		{
			string = "const BYTE name_me[]={";
			for (size_t i = 0; i < count; i++)
			{
				if (mask[i])
					string.cat_sprnt("0x%02X,", bytes[i]);
				else
					string.cat_sprnt("0x%02X,", settings.maskByte);
			}
			string.remove_last();
			string += "};";
		}
	}

	// Right trim wildcards from signiture if they exist
	void trim()
	{
		size_t len = 0;
		for (size_t i = (bytes.size() - 1); i > 0; i--)
		{
			if (!mask[i])
				len++;
			else
				break;
		}

		if (len)
		{
			size_t newSize = (bytes.size() - len);
			bytes.resize(newSize);
			mask.resize(newSize);
		}
	}

	// Return wildcard/mask count
	size_t wildcards() const
	{
		size_t count = 0;

		// TODO: Vectorize this functions for speed?
		size_t size = bytes.size();
		for (size_t i = 0; i < size; ++i)
		{
			if (!mask[i])
				count++;
		}

		return count;
	}

    // Return TRUE is there is one or more wildcard/mask bytes
    __inline BOOL hasMask() const
    {
		return memchr(mask.data(), 0, bytes.size()) != NULL;
    }

    // ------------------------------------------------------------------------

    SIG& operator+=(const SIG &rhs)
    {
        // Append another sig to me
        bytes.insert(bytes.end(), rhs.bytes.begin(), rhs.bytes.end());
        mask.insert(mask.end(), rhs.mask.begin(), rhs.mask.end());
        return *this;
    }
};

// Search.cpp
enum SSTATUS
{
	NOT_FOUND,	// Signature not found error
	UNIQUE,		// Unique, single instance found
	NOT_UNIQUE	// Not unique, more than one instance found
};
SSTATUS SearchSignature(const SIG &sig);
void SearchCleanup();

// Signature.cpp
void CreateFunctionSig();
void CreateAddressSig();
void CreateAddressRangeSig();
void OutputSignature(const SIG &sig, ea_t address, UINT32 offset);
