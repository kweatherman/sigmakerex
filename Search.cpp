
// Search for binary signature pattern support
#include "SigMaker.h"


BOOL g_isAVX2Supported = 0;

//#define FORCE_REF_SEARCH

// Local search data container
struct SearchData
{
	// Clone IDB byte database to RAM for fast pattern scanning
	PBYTE buffer;
	size_t size;

	BOOL CloneIdb()
	{
		if (!buffer)
		{
			LOG_VERBOSE(__FUNCTION__ ": min_ea: 0x%llX, max_ea: 0x%llX, size: 0x%llX\n\n", (UINT64) inf_get_min_ea(), (UINT64) inf_get_max_ea(), (UINT64) (inf_get_max_ea() - inf_get_min_ea()));

			// Allocate page buffer to encompass the whole the IDB region
			size = (UINT64) (inf_get_max_ea() - inf_get_min_ea());
			buffer = (PBYTE) VirtualAlloc(NULL, size + 32, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
			if (buffer)
			{
				// Copy the IDB bytes to the buffer
				// Simple loop much faster than: get_qword(), get_bytes(), etc.
				// Note: For bytes that don't exist in the PE file, get_db_byte() will return 0xFF.
				ea_t  currentEa = inf_get_min_ea();
				PBYTE ptr = buffer;
				size_t count = size;

				do
				{
					*ptr = (BYTE) get_db_byte(currentEa);
					++currentEa, ++ptr, --count;

				} while (count);
			}
			else
				msg(MSG_TAG "** Failed to allocate the clone RAM buffer of size: 0x%llX ! **\n", size);
		}

		return buffer != NULL;
	}

	void Cleanup()
	{
		if (buffer)
		{
			VirtualFree(buffer, 0, MEM_RELEASE);
			buffer = NULL;
		}
	}

	// Most post 2013 Intel and 2015 AMD CPUs have "Advanced Vector Extensions 2" (AVX2) support
	// 2022 86.65% https://store.steampowered.com/hwsurvey/
	// https://en.wikipedia.org/wiki/Advanced_Vector_Extensions#CPUs_with_AVX2
	BOOL TestAVX2Support()
	{
		enum { EAX, EBX, ECX, EDX };
		int regs[4];

		// Highest Function Parameter
		__cpuid(regs, 0);
		if (regs[EAX] >= 7)
		{
			// Extended Features
			__cpuid(regs, 7);
			return (regs[EBX] & /*AVX2*/ (1 << 5)) != 0;
		}
		return FALSE;
	}

	BOOL hasAVX2;
	SearchData() : buffer(NULL), size(0)
	{
		hasAVX2 = TestAVX2Support();
		g_isAVX2Supported = hasAVX2;
	}
	~SearchData()
	{
		Cleanup();
	}

} static searchData;

void SearchCleanup()
{
	searchData.Cleanup();
}

//-------------------------------------------------------------------------------------------------
/*
AVX2 pattern scanner based on Wojciech Mula's avx2_strstr_anysize()
  http://0x80.pl/articles/simd-strfind.html#generic-sse-avx2

Rules:
1) Expects input data to be at least align 32
2) SIG must be at least 3 byte in length
3) SIG must be trimmed (the first and last of the pattern can't be a wildcard/mask)
*/

static inline UINT32 get_first_bit_set(UINT32 x)
{
	// Generates a single BSF instruction
	unsigned long ret;
	_BitScanForward(&ret, x);
	return (UINT32) ret;
}

static inline UINT32 clear_leftmost_set(UINT32 value)
{
	// Generates a single BLSR instruction
	return value & (value - 1);
}

// Like memcmp() but takes a 3rd 'mask' argument
// Note: Tried optimizing, has little effect on cumulative scan speed
int memcmp_mask(const BYTE *buffer1, const BYTE *buffer2, const BYTE *mask2, size_t count)
{
	while (count--)
	{
		if (*mask2)
		{
			if (*buffer1 != *buffer2)
				return -1;
		}

		buffer1++, buffer2++, mask2++;
	};
	return 0;
}

// Find signature pattern in memory
PBYTE FindSignatureAVX2(PBYTE data, size_t size, const SIG &sig, BOOL hasWildcards)
{
	const BYTE *pat = sig.bytes.data();
	size_t patLen = sig.bytes.size();
	size_t patLen1 = (patLen - 1);
	size_t patLen2 = (patLen - 2);

	// Fill 'first' and 'last' with the first and last pattern byte respectively
	const __m256i first = _mm256_set1_epi8(pat[0]);
	const __m256i last = _mm256_set1_epi8(pat[patLen1]);

	if(!hasWildcards)
	{
		// A little faster without wildcards

		// Scan 32 bytes at the time..
		for (size_t i = 0; i < size; i += 32)
		{
			// Load in the next 32 bytes of input first and last
			// Can use align 32 bit read for first since the input is page aligned
			const __m256i block_first = _mm256_load_si256((const __m256i*) (data + i));
			const __m256i block_last = _mm256_loadu_si256((const __m256i*) (data + i + patLen1));

			// Compare first and last data to get 32byte masks
			const __m256i eq_first = _mm256_cmpeq_epi8(first, block_first);
			const __m256i eq_last = _mm256_cmpeq_epi8(last, block_last);

			// AND the equality masks and into a 32 bit mask
			UINT32 mask = _mm256_movemask_epi8(_mm256_and_si256(eq_first, eq_last));

			// Do pattern compare between first and last position if we got our first and last at this data position
			while (mask != 0)
			{
				UINT32 bitpos = get_first_bit_set(mask);
				if (memcmp(data + i + bitpos + 1, pat + 1, patLen2) == 0)
				{
					return data + i + bitpos;
				}
				mask = clear_leftmost_set(mask);
			};
		}
	}
	else
	{
		// Pattern scan with wildcards mask
		const BYTE *msk = sig.mask.data();

		for (size_t i = 0; i < size; i += 32)
		{
			const __m256i block_first = _mm256_load_si256((const __m256i*) (data + i));
			const __m256i block_last = _mm256_loadu_si256((const __m256i*) (data + i + patLen1));

			const __m256i eq_first = _mm256_cmpeq_epi8(first, block_first);
			const __m256i eq_last = _mm256_cmpeq_epi8(last, block_last);

			UINT32 mask = _mm256_movemask_epi8(_mm256_and_si256(eq_first, eq_last));

			// Do a byte pattern w/mask compare between first and last position if we got our first and last
			while (mask != 0)
			{
				UINT32 bitpos = get_first_bit_set(mask);
				if (memcmp_mask(data + i + bitpos + 1, pat + 1, msk + 1, patLen2) == 0)
				{
					return data + i + bitpos;
				}
				mask = clear_leftmost_set(mask);
			};
		}
	}

	return NULL;
}


// ------------------------------------------------------------------------------------------------

// Find signature pattern in memory
// Base memory search reference, about 10x slower than the AVX2 version
PBYTE FindSignature(PBYTE input, size_t inputLen, const SIG &sig, BOOL hasWildcards)
{
	if (!hasWildcards)
	{
		// If no wildcards, faster to use a memcmp() type
		const BYTE *pat = sig.bytes.data();
		const BYTE *end = (input + inputLen);
		const BYTE first = *pat;
		size_t sigLen = sig.bytes.size();

		// Setup last in the pattern length byte quick for rejection test
		size_t lastIdx = (sigLen - 1);
		BYTE last = pat[lastIdx];

		for (PBYTE ptr = input; ptr < end; ++ptr)
		{
			if ((ptr[0] == first) && (ptr[lastIdx] == last))
			{
				if (memcmp(ptr+1, pat+1, sigLen-2) == 0)
					return ptr;
			}
		}
	}
	else
	{
		const BYTE *pat = sig.bytes.data();
		const BYTE *msk = sig.mask.data();
		const BYTE *end = (input + inputLen);
		const BYTE first = *pat;
		size_t sigLen = sig.bytes.size();
		size_t lastIdx = (sigLen - 1);
		BYTE last = pat[lastIdx];

		for (PBYTE ptr = input; ptr < end; ++ptr)
		{
			if ((ptr[0] == first) && (ptr[lastIdx] == last))
			{
				const BYTE *patPtr = pat+1;
				const BYTE *mskPtr = msk+1;
				const BYTE *memPtr = ptr+1;
				BOOL found = TRUE;

				for (int i = 0; (i < sigLen-2) && (memPtr < end); ++mskPtr, ++patPtr, ++memPtr, i++)
				{
					if (!*mskPtr)
						continue;

					if (*memPtr != *patPtr)
					{
						found = FALSE;
						break;
					}
				}

				if (found)
					return ptr;
			}
		}
	}

	return NULL;
}

// ------------------------------------------------------------------------------------------------

// Reference version search
static SSTATUS SearchSignature(PBYTE input, size_t inputLen, const SIG &sig)
{
	size_t sigSize = sig.bytes.size();
	size_t len = inputLen;
	size_t count = 0;
	BOOL hasWildcards = sig.hasMask();

	inputLen -= sigSize;

	// Search for signature match..
    PBYTE match = FindSignature(input, len, sig, hasWildcards);
	while (match)
	{
		// Stop now if we've hit two matches
		if (++count >= 2)
			break;

		++match;
		len = (inputLen - (int) (match - input));
		if (len < sigSize)
			break;

		// Next search
        match = FindSignature(match, len, sig, hasWildcards);
	};

	SSTATUS status;
	switch (count)
	{
		case 0: status = SSTATUS::NOT_FOUND; break;
		case 1: status = SSTATUS::UNIQUE; break;
		default: status = SSTATUS::NOT_UNIQUE; break;
	};

	// Only happens when there is an error in the search algorithm during development/testing
	if (status == SSTATUS::NOT_FOUND)
	{
		msg("\n** " __FUNCTION__ ": Sig not found! **\n");
		qstring tmp;
		sig.ToIdaString(tmp);
		msg("(%u) \"%s\"\n\n", (UINT32) sig.bytes.size(), tmp.c_str());
	}

	return status;
}

// Fast AVX2 based search
static SSTATUS SearchSignatureAVX2(PBYTE input, size_t inputLen, const SIG &sig)
{
	size_t sigSize = sig.bytes.size();
	size_t len = inputLen;
	size_t count = 0;
	BOOL hasWildcards = sig.hasMask();

	inputLen -= sigSize;

	PBYTE match = FindSignatureAVX2(input, len, sig, hasWildcards);
	while (match)
	{
		if (++count >= 2)
			break;

		++match;
		len = (inputLen - (int) (match - input));
		if (len < sigSize)
			break;

		match = FindSignatureAVX2(match, len, sig, hasWildcards);
	};

	SSTATUS status;
	switch (count)
	{
		case 0: status = SSTATUS::NOT_FOUND; break;
		case 1: status = SSTATUS::UNIQUE; break;
		default: status = SSTATUS::NOT_UNIQUE; break;
	};

	// Only happens when there is an error in the search algorithm during development/testing
	if (status == SSTATUS::NOT_FOUND)
	{
		msg("\n** " __FUNCTION__ ": Sig not found! **\n");
		qstring tmp;
		sig.ToIdaString(tmp);
		msg("(%u) \"%s\"\n\n", (UINT32) sig.bytes.size(), tmp.c_str());
	}
	return status;
}

// Search for signature pattern, returning a status result
SSTATUS SearchSignature(const SIG &sig)
{
	// Setup IDB RAM clone on first scan
	if (!searchData.CloneIdb())
		return SSTATUS::NOT_FOUND;

	#ifndef FORCE_REF_SEARCH
	if (searchData.hasAVX2)
		return SearchSignatureAVX2(searchData.buffer, searchData.size, sig);
	else
	#else
	#pragma message(__LOC2__ "   ** Force use reference search switch on! **")
	#endif
	{
		static BOOL warnOnce = TRUE;
		if ((settings.outputLevel >= SETTINGS::LL_VERBOSE) && warnOnce)
		{
			warnOnce = FALSE;
			msg(" * Using non-AVX2 reference search *\n");
		}

		return SearchSignature(searchData.buffer, searchData.size, sig);
	}
}
