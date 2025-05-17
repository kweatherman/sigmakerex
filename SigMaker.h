
// Common and shared
#pragma once

#include "StdAfx.h"
#include <vector>

#include "Settings.h"

extern BOOL g_isAVX2Supported;

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
    void ToIdaString(__out qstring &string, BOOL singleByteWildCard = FALSE) const
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

	// Right trim wildcards from signature if they exist
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

		if (g_isAVX2Supported)
		{
			
			size_t N = mask.size();

			// Round up to next multiple of 32
			size_t M = (N + 31) & ~size_t(31);

			const __m256i index = _mm256_setr_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31);
			const __m256i sign_flip = _mm256_set1_epi8((char)0x80);
			const __m256i ones = _mm256_set1_epi8(1);
			const __m256i zeros = _mm256_setzero_si256();

			for (size_t i = 0; i < M; i += 32)
			{
				// Load up to 32 bytes
				__m256i chunk = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&mask[i]));

				// Compute how many bytes are still valid in the mask
				uint32_t urem = std::min<uint32_t>(N - i, 255);
				__m256i rem_vec = _mm256_set1_epi8((char)urem);

				// Mask out-of-bounds bytes
				__m256i rem_flipped = _mm256_xor_si256(rem_vec, sign_flip);
				__m256i idx_flipped = _mm256_xor_si256(index, sign_flip);
				__m256i valid_mask = _mm256_cmpgt_epi8(rem_flipped, idx_flipped);

				// For invalid bytes, insert 1 (so they're not zero)
				__m256i data = _mm256_blendv_epi8(ones, chunk, valid_mask);

				// Find wildcards (== 0)
				__m256i cmp = _mm256_cmpeq_epi8(data, zeros);

				// Count matching zero bytes
				uint32_t bitmask = _mm256_movemask_epi8(cmp);
				count += _mm_popcnt_u32(bitmask);
			}
		}
		else
		{
			size_t size = bytes.size();
			for (size_t i = 0; i < size; ++i)
			{
				if (!mask[i])
					count++;
			}

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
