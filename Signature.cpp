
// Main signature generation code
#include "SigMaker.h"
#include <algorithm>
#include <list>

#define WAIT_BOX_UPDATE() { if (WaitBox::isUpdateTime()) WaitBox::updateAndCancelCheck(); }

// Unique signature match container
struct SIGMATCH
{
	SIG sig;
	ea_t ea;
	UINT32 size;
    UINT32 wildcards;

	SIGMATCH(SIG &_sig, ea_t match_ea)
	{
        _sig.trim();
		sig = _sig;
		ea = match_ea;
		size = (UINT32) _sig.bytes.size();
        wildcards = (UINT32) _sig.wildcards();
	}

	bool operator <(const SIGMATCH &b) const
	{
		//return size < b.size;
        return std::pair(size, wildcards) < std::pair(b.size, b.wildcards);
	}
};
typedef std::list<SIGMATCH> UNIQUELIST;

// Container for instruction signature "siglets"
typedef std::vector<SIG> SIGLETS;


// Output signature to the IDA log pane
void OutputSignature(const SIG &sig, ea_t address, UINT32 offset)
{
	if (offset == 0)
		msg("SIG: 0x" EAFORMAT ", %u bytes %u, wildcards.\n", address, (UINT32) sig.bytes.size(), (UINT32) sig.wildcards());
	else
		msg("SIG: 0x" EAFORMAT ", @ Offset: 0x%X, %u bytes, %u wildcards\n", address, offset, (UINT32) sig.bytes.size(), (UINT32) sig.wildcards());

	// Always output IDA format
	qstring tmp;
	sig.ToIdaString(tmp);
	msg("IDA: \"%s\"\n", tmp.c_str());

	switch (settings.outputFormat)
	{
		// Escape encoded binary with ASCII mask "code" style in two strings.
		// E.g. "\x33\x9A\xFA\x00\x00\x00\x00\x45\x68", "xxxxxxx????xx"
		case SETTINGS::OF_CODE:
		{
			qstring code;
			sig.ToCodeString(code);
			qstring mask;
			sig.ToMaskString(mask);
			tmp.sprnt("\"%s\", \"%s\"", code.c_str(), mask.c_str());
			msg("%s\n", tmp.c_str());
		}
		break;

		// Like "code" style, but byte string with inlined wildcard bytes
		// E.g. "\x33\x9A\xFA\xAD\xAD\xAD\xAD\x45\x68", where 0xAD is the wildcard bytes
		case SETTINGS::OF_INLINE:
		{
			qstring bytes;
			sig.ToInlineString(bytes);
			msg("\"%s\"\n", bytes.c_str());
			qstring comment;
			comment.sprnt("// \"%s\"\n", tmp.c_str());
			tmp.sprnt("%s%s\n", comment.c_str(), bytes.c_str());
			if (offset)
			{
				qstring offstr;
				offstr.sprnt("const UINT32 name_me_offset = 0x%X;", offset);
				msg("\"%s\"\n", offstr.c_str());
				tmp += offstr;
			}
			msg("\"const BYTE MASK_BYTE = 0x%X;\"\n", settings.maskByte);
		}
		break;
	};
	WaitBox::processIdaEvents();

	SetClipboard(tmp.c_str());
}

// ------------------------------------------------------------------------------------------------
// Instruction analysis

static inline BOOL isJmpCntl(UINT32 type) { return((type >= NN_ja) && (type <= NN_jz)); }             // Return TRUE if a conditional jump instruction
static inline BOOL isJmpNotCntl(UINT32 type) { return((type >= NN_jmp) && (type <= NN_jmpshort)); }   // Return TRUE if a non-conditional jump instruction
static inline BOOL isCall(UINT32 type) { return((type >= NN_call) && (type <= NN_callni)); }          // Return TRUE if is a call instruction
static inline BOOL IsIdbAddress(ea_t address) { return((address >= inf.omin_ea) && (address < inf.omax_ea)); }  // Returns TRUE if address is inside this IDB

// Return the instruction operand offset if it has one
static UINT32 OperandOffset(__in insn_t &cmd)
{
    // For x86/AMD64 this will only a few max
    for (UINT32 i = 0; i < UA_MAXOP; i++)
    {
        // Hit end of opcode entries?
		optype_t type = cmd.ops[i].type;
		if ((type == o_void) || (type == (o_idpspec5 + 1)))
            return 0;
        else
        // Has an operand value
        if (cmd.ops[i].offb != 0)
            return cmd.ops[i].offb;
    }
    return 0;
}

// Get largest value of the instruction operands be it a displacement or immediate value, etc., and considering the MSB/sign bit
static ea_t LargestOperandValue(insn_t &cmd, ea_t test_ea)
{
	// IDA conveniently returns absolute addresses (not relative ones)

	// TODO: For the sign assumptions here, could check for AWE aware flag (PE header flag IMAGE_FILE_LARGE_ADDRESS_AWARE) for 32bit targets
    // Rare PE header flag for 32bit but a possibility still.
    #ifndef __EA64__
    static const ea_t HIGH_BIT = 0x80000000;
    #else
    static const ea_t HIGH_BIT = 0x8000000000000000;
    #endif

    ea_t result = 0;

    for (UINT32 i = 0; i < UA_MAXOP; i++)
    {
        optype_t type = cmd.ops[i].type;
        if ((type == o_void) || (type == (o_idpspec5 + 1)))
            break;
        else
        {
            ea_t value = (ea_t) cmd.ops[i].value;
            //if ((value & HIGH_BIT) && (type == o_imm))
            //    msg(EAFORMAT " v: " EAFORMAT "\n", test_ea, value);

            // Ignore signed immediate value, assume it's a flag value that can be ignored
            if (!((value & HIGH_BIT) && (type == o_imm)))
                if (value > result)
                    result = value;

            // Ignore signed displacements and memory references
            ea_t adress = cmd.ops[i].addr;
            if (!((adress & HIGH_BIT) && ((type == o_displ) || (type == o_mem))))
                if (adress > result)
                    result = adress;

            //if (result & HIGH_BIT)
            //    msg(EAFORMAT " " EAFORMAT " " EAFORMAT " t: %d\n", test_ea, value, adress, type);
        }
    }

    return result;
}

// Decode an instruction into a sig container
static void AddInst(__in_opt func_t *pfn, __in insn_t &cmd, __inout SIG &sig)
{
    UINT32 offb = OperandOffset(cmd);
    if (offb != 0)
    {
        // Filter out all call targets
        BOOL filter = FALSE;
        if (isCall(cmd.itype))
            filter = TRUE;
        else
        // Check jump targets
        if (isJmpCntl(cmd.itype) || isJmpNotCntl(cmd.itype))
        {
			// If we have function bounds, test for membership
			if (pfn)
			{
				// Filter if jump target is outside of our function
				ea_t target_ea = LargestOperandValue(cmd, cmd.ea);
				filter = !func_contains(pfn, target_ea);
			}
			else
			// Else, keep short jumps and filter the rest
			{
				if (cmd.size != 2)
					filter = TRUE;
			}
        }
        else
        {
            // Filter intermediate values that are probably an address
            if (ea_t value = LargestOperandValue(cmd, cmd.ea))
                filter = IsIdbAddress(value);
        }

        if (filter)
        {
            // Save the leading instruction bytes and wildcard the rest
            sig.AddBytes(cmd.ea, offb);
            sig.AddWildcards(cmd.size - offb);
        }
        else
            sig.AddBytes(cmd.ea, cmd.size);
    }
    else
		// No operand value
		sig.AddBytes(cmd.ea, cmd.size);
}


// ------------------------------------------------------------------------------------------------

// Dump a function's siglets for development
static void DumpFuncSiglets(__in func_t *pfn, __in SIGLETS &siglets)
{
	qstring name;
	get_func_name(&name, pfn->start_ea);
	msg("--------------------- " EAFORMAT " '%s' ---------------------\n", pfn->start_ea, name.c_str());

	ea_t current_ea = pfn->start_ea;
	size_t count = siglets.size();
	for (size_t i = 0; i < count; i++)
	{
		SIG &siglet = siglets[i];
		UINT32 size = (UINT32) siglet.bytes.size();

		msg("[%04u] " EAFORMAT ": ", i, current_ea);
		qstring str;
		siglet.ToIdaString(str);
		msg("(%u) \"%s\"", size, str.c_str());
		qstring disasm;
		GetDisasmText(current_ea, disasm);
		msg("  '%s'\n", disasm.c_str());
		current_ea += size;
	}

	msg("--------------------- " EAFORMAT " '%s' ---------------------\n", pfn->end_ea, name.c_str());
}

// Decode instruction into a siglet
// Returns instruction/alignment section on return, else <= 0 on error
static int InstToSig(__in_opt func_t *pfn, ea_t current_ea, __out SIG &siglet)
{
	// Decode instruction at this address
	insn_t cmd;
	int decodeSize = decode_insn(&cmd, current_ea);
	int itemSize = (int) get_item_size(current_ea);
	if (decodeSize <= 0)
	{
		// Decode failure
		// TODO: Fix bad instruction cases if/when encountered
		msg(MSG_TAG "** " __FUNCTION__ ": Decode failure @ 0x" EAFORMAT "! decodeSize: %d, itemSize: %d **\n", current_ea, decodeSize, itemSize);
		return -1;
	}

	if (decodeSize != itemSize)
	{
		// 99% of the time these are just "align" blocks
		flags_t flags = get_flags_ex(current_ea, 0);
		if (is_align(flags))
		{
			// Wildcard the itemSize count of bytes
			siglet.AddWildcards(itemSize);
		}
		else
		{
			// TODO: Fix more anomalous instruction cases as they encountered..
			msg(MSG_TAG "* " __FUNCTION__ ": Decode anomaly @ 0x" EAFORMAT "! decodeSize: %d, itemSize: %d *\n", current_ea, decodeSize, itemSize);
			qstring outbuf;
			IdaFlags2String(flags, outbuf);
			msg(" F: %08X, \"%s\"\n", flags, outbuf.c_str());
			qstring disasm;
			GetDisasmText(current_ea, disasm);
			msg(" '%s'\n\n", disasm.c_str());
			return -1;
		}
	}
	else
	{
		// Add instruction to signature
		AddInst(pfn, cmd, siglet);
	}

	return itemSize;
}

// Convert function instructions into an array of "siglets"
// For disjointed chunk functions, only processes the first/entry chunk
static BOOL FuncToSiglets(__in func_t *pfn, __out SIGLETS &siglets)
{
	// Iterate function instructions
	func_item_iterator_t fIt;
	if (!fIt.set(pfn))
	{
		msg(MSG_TAG "** Failed to init function iterator **\n");
		return FALSE;
	}

	ea_t expected_ea = BADADDR;
	do
	{
		// Decode next instruction
		ea_t current_ea = fIt.current();

		// Detect if we walked into some other function body
		// Will happen for the functions that have chunks spread out over different address ranges.
		// Also for the occasional broken function definition too.
		if ((current_ea != expected_ea) && (expected_ea != BADADDR))
		{
			// We'll stop here, keep what we have, and return
			msg(MSG_TAG "* Into non-contiguous chunk @ 0x" EAFORMAT ", expected " EAFORMAT ". Signature truncated. * \n", current_ea, expected_ea);
			break;
		}

		// Add next instruction siglet
		SIG siglet;
		int itemSize = InstToSig(pfn, current_ea, siglet);
		if (itemSize >= 1)
			siglets.push_back(siglet);
		else
			return FALSE;

		expected_ea = (current_ea + itemSize);

	} while (fIt.next_not_tail());

	return TRUE;
}

// Build a full function signature combined from a siglets array
static void BuildFuncSig(__in const SIGLETS &siglets, __out SIG &sig)
{
	for (const SIG &siglet: siglets)
		sig += siglet;
}

// Look for a unique sig at given function siglet boundary position
static ea_t FindSigAtFuncAddress(ea_t current_ea, ea_t end_ea, size_t sigIndex, const SIGLETS &siglets, __out SIG &outsig)
{
	/*
	TODO: Currently sig candidates are generated from instruction boundary lengths.
	Walking by sub-instruction lengths could result in more smallish sig canidates.
	But already relativity slow from all the uniqueness queries, this would increase the amount of searches (thus the time) even more.
	Although typically using instruction lengths as it is returns plenty of canidates in the 5'ish byte length anyhow.
	*/

	// Expand our sig until we either find a unique one or we hit the end address
    SIG sig;
	size_t sigByteSize = 0;
    size_t sigletCount = siglets.size();

	for (size_t i = sigIndex; i < sigletCount; i++)
	{
		const SIG &siglet = siglets[i];
		sig += siglet;
		size_t byteSize = siglet.bytes.size();
		sigByteSize += byteSize;

		// If sig byte size is MIN_SIG_SIZE or larger check if the sig is unique
		if (sigByteSize >= MIN_SIG_SIZE)
		{
			// Skip the cases like "E8 ?? ?? ?? ??"
			size_t nonMaskSize = (sigByteSize - sig.wildcards());
			if (nonMaskSize > 1)
			{
				// Make a trimmed temp copy for further testing and faster scan speed
				SIG tmp = sig;
				tmp.trim();

				// Skip cases like "E8 ?? ?? ?? ??"
				if (tmp.bytes.size() >= MIN_SIG_SIZE)
				{
					// Unique sig now?
					SSTATUS status = SearchSignature(tmp);
					if (status == SSTATUS::UNIQUE)
					{
						// Yes, return it
						outsig = tmp;
						return current_ea;
					}
					else
					// To cover a case that can only happen during development
					if (status == SSTATUS::NOT_FOUND)
						return BADADDR;

					WAIT_BOX_UPDATE();
				}
			}
		}

		current_ea += (ea_t) byteSize;
		if (current_ea >= end_ea)
			break;
	}

    return BADADDR;
}


// Find minimal at instruction boundary, inside a function (already known to be unique), signature.
static ea_t FindMinimalFuncSig(ea_t start_ea, ea_t end_ea, __in const SIGLETS &siglets, __out SIG &outsig)
{
	// Walk through each siglet from the top down at instruction boundaries
	UNIQUELIST canidates;
	ea_t current_ea = start_ea;
	size_t count = siglets.size();

	for (size_t i = 0; i < count; i++)
	{
		// Try to find a unique sig at this address for siglet position
		const SIG &siglet = siglets[i];
		SIG sig;
		ea_t result_ea = FindSigAtFuncAddress(current_ea, end_ea, i, siglets, sig);
		if (result_ea != BADADDR)
		{
			// Save candidate
			SIGMATCH canidate(sig, current_ea);
			canidates.push_back(canidate);

			// If at MIN_SIG_SIZE or less and no wildcards stop with this one
			if ((canidate.size <= MIN_SIG_SIZE) && (canidate.wildcards == 0))
			{
				LOG_VERBOSE(__FUNCTION__ ": Found ideal canidate: %u, %u.\n", canidate.size, canidate.wildcards);
				break;
			}
		}

		current_ea += (ea_t) siglet.bytes.size();
	}

	// Sport unique sig canidates by ascending primarily size, secondarily by 2nd wildcard count
	canidates.sort();

	if (settings.outputLevel >= SETTINGS::LL_VERBOSE)
	{
		msg("\nUnique sig canidates: %u\n", (UINT32)canidates.size());
		for (SIGMATCH &c: canidates)
		{
			qstring str;
			c.sig.ToIdaString(str);
			msg(EAFORMAT ": (%02u, %02u) '%s'\n", c.ea, c.size, c.wildcards, str.c_str());
		}
		WaitBox::processIdaEvents();
	}

	// Return the topmost/best
	outsig = canidates.front().sig;
	return canidates.front().ea;
}

// Find unique sig at function (already known to be unique) entry point downward
// The size will be anywhere from MIN_SIG_SIZE to the entire function body size
static ea_t FindFuncEntryPointSig(ea_t start_ea, __in SIG &funcSig, __out SIG &outsig)
{
    // Walk function sig down a byte at the time until we build a unique sig
    funcSig.trim();
	size_t sigSize = funcSig.bytes.size();
    size_t sigByteSize = 0;
    outsig.bytes.reserve(sigSize);
    outsig.mask.reserve(sigSize);

	for (size_t i = 0; i < sigSize; i++)
	{
		// Append next byte from function sig
        outsig.bytes.push_back(funcSig.bytes[i]);
        outsig.mask.push_back(funcSig.mask[i]);
        sigByteSize += 1;

		// If sig byte size is MIN_SIG_SIZE or greater check if the sig is unique
        if (sigByteSize >= MIN_SIG_SIZE)
        {
			// Make a trimmed temp copy for further testing and faster scan speed
			SIG tmp = outsig;
			tmp.trim();

			// Skip cases like "E8 ?? ?? ?? ??"
			if (tmp.bytes.size() >= MIN_SIG_SIZE)
			{
				// Unique now?
				SSTATUS status = SearchSignature(tmp);
				if (status == SSTATUS::UNIQUE)
				{
					// Yes, return it
					outsig = tmp;
					return start_ea;
				}
				else
				// To cover a case that can only happen during development
				if (status == SSTATUS::NOT_FOUND)
					return BADADDR;

				WAIT_BOX_UPDATE();
			}
        }
	}

    return BADADDR;
}

// Find the optimal function (already known to be unique) signature based on user criteria setting
ea_t FindFuncSig(__in const func_t *pfn, __in const SIGLETS &siglets, __in SIG &funcSig, __out SIG &outsig, UINT32 &offset)
{
    switch (settings.funcCriteria)
    {
		// Sig from function entry point downward
        case SETTINGS::FUNC_ENTRY_POINT:
		{
			ea_t result_ea = FindFuncEntryPointSig(pfn->start_ea, funcSig, outsig);
			offset = 0;
			return result_ea;
		}
        break;

		// Minimal optimal function sig
		case SETTINGS::FUNC_MIN_SIZE:
		{
			ea_t result_ea = FindMinimalFuncSig(pfn->start_ea, pfn->end_ea, siglets, outsig);
			offset = (UINT32) (result_ea - pfn->start_ea);
			return result_ea;
		}
		break;

		// Full function sig
		case SETTINGS::FUNC_FULL:
		{
			funcSig.trim();
            outsig = funcSig;
			offset = 0;
            return pfn->start_ea;
		}
		break;
    };

    return BADADDR;
}


// ------------------------------------------------------------------------------------------------

// Look for a unique function sig at given address
// Returns base address of sig, or BADADDR on failure
static ea_t FindSigAtFuncAddress(ea_t current_ea, __in func_t *pfn, __out SIG &outsig)
{
	// Expand our sig until we either find a unique one or we hit the end address..
	SIG sig;
	size_t sigByteSize = 0;
	ea_t end_ea = pfn->end_ea;

	while ((current_ea != BADADDR) && (current_ea < end_ea))
	{
		SIG siglet;
		int itemSize = InstToSig(pfn, current_ea, siglet);
		if (itemSize >= 1)
			sig += siglet;
		else
			return BADADDR;
		sigByteSize += (size_t) itemSize;

		// If sig byte size is MIN_SIG_SIZE or larger check if the sig is unique
		if (sigByteSize >= MIN_SIG_SIZE)
		{
			// Make a trimmed temp copy for further testing and faster scan speed
			SIG tmp = sig;
			tmp.trim();

			// Skip cases like "E8 ?? ?? ?? ??"
			if (tmp.bytes.size() >= MIN_SIG_SIZE)
			{
				// Unique sig now?
				SSTATUS status = SearchSignature(tmp);
				if (status == SSTATUS::UNIQUE)
				{
					// Yes, return it
					outsig = tmp;
					return current_ea;
				}
				else
				// To cover a case that can only happen during development
				if (status == SSTATUS::NOT_FOUND)
					return BADADDR;

				WAIT_BOX_UPDATE();
			}
		}

		current_ea += (ea_t) itemSize;
		if (current_ea >= end_ea)
			break;
	}

	return BADADDR;
}

// Look for a unique sig at given address; same as above sans function requirement
// Returns base address of sig, or BADADDR on failure
static ea_t FindSigAtAddress(ea_t current_ea, __out SIG &outsig)
{
	// Expand our sig until we either find a unique one, we run into a function, or we hit a non-address
	SIG sig;
	size_t sigByteSize = 0;

	while (TRUE)
	{
		// Bail if we are no longer inside of a valid code space
		flags_t flags = get_flags_ex(current_ea, 0);
		if (!is_code(flags))
		{
			LOG_VERBOSE(__FUNCTION__ ": 0x" EAFORMAT " no longer in a valid code space.\n", current_ea);
			break;
		}

		// Check if we walked into a function now
		// The assumption is the user wants a sig for some place non inside of a function and now we
		// walked into one at or past the entry point.
		//if(get_func(current_ea))
		if (is_func(flags))
		{
			LOG_VERBOSE(__FUNCTION__ ": 0x" EAFORMAT " walked into a function.\n", current_ea);
			break;
		}

		SIG siglet;
		int itemSize = InstToSig(NULL, current_ea, siglet);
		if (itemSize >= 1)
			sig += siglet;
		else
			return BADADDR;
		sigByteSize += (size_t)itemSize;

		// If sig byte size is MIN_SIG_SIZE or larger check if the sig is unique
		if (sigByteSize >= MIN_SIG_SIZE)
		{
			// Make a trimmed temp copy for further testing and faster scan speed
			SIG tmp = sig;
			tmp.trim();

			// Skip cases like "E8 ?? ?? ?? ??"
			if (tmp.bytes.size() >= MIN_SIG_SIZE)
			{
				// Unique sig now?
				SSTATUS status = SearchSignature(tmp);
				if (status == SSTATUS::UNIQUE)
				{
					// Yes, return it
					outsig = tmp;
					return current_ea;
				}
				else
				// To cover a case that can only happen during development
				if (status == SSTATUS::NOT_FOUND)
					return BADADDR;

				WAIT_BOX_UPDATE();
			}
		}

		current_ea += (ea_t) itemSize;
	}

	return BADADDR;
}

// Attempt to find a function entry code reference sig and output it
BOOL FindFuncXrefSig(ea_t func_ea)
{
	// Get first cref to the function if there is one
	ea_t ref_ea = get_first_cref_to(func_ea);
	if (ref_ea == BADADDR)
	{
		LOG_VERBOSE("No crefs available.\n");
	}
	else
	{
		// Gather target function references best sig canidates..
		UNIQUELIST canidates;

		// Override maximum ref limit search if setting exists, else use unlimited
		// TODO: Could be situations where we look at 100's, if not thousands of refs, trying a sig at each taking seconds if not minutes.
		// Might need a default max limit and/or iteration time limit.
		UINT32 refLimit = ((settings.maxScanRefCount > 0) ? settings.maxScanRefCount : UINT_MAX);
		UINT32 sigCount = 0;

		while ((ref_ea != BADADDR) && (sigCount < refLimit))
		{
			func_t *pfn = get_func(ref_ea);
			if (pfn)
			{
				LOG_VERBOSE("[%u] Function ref @ 0x" EAFORMAT ", Func: 0x" EAFORMAT "\n", sigCount, ref_ea, pfn->start_ea);

				// Look for a unique sig from reference branch down
				SIG sig;
				ea_t sig_ea = FindSigAtFuncAddress(ref_ea, pfn, sig);
				if (sig_ea != BADADDR)
				{
					// Save candidate
					SIGMATCH canidate(sig, sig_ea);
					canidates.push_back(canidate);

					// The ref sigs are going to start with the reference branch instruction.
					// So we are looking at least a 5 byte sig with wildcards to begin with.
					// Bail out now if we got a good minimal sig.
					static const UINT32 BRANCH_INSTRUCTION_SIZE = 5; // E.g. "E8 ?? ?? ?? ??"
					if ((canidate.size <= (BRANCH_INSTRUCTION_SIZE + MIN_SIG_SIZE)) && (canidate.wildcards <= (BRANCH_INSTRUCTION_SIZE - 1)))
					{
						LOG_VERBOSE(__FUNCTION__ ": Found good minimal canidate: %u, %u.\n", canidate.size, canidate.wildcards);
						break;
					}
				}
				else
					LOG_VERBOSE(" Ref not unique or error occured, skipped.\n");
			}

			sigCount++;
			ref_ea = get_next_cref_to(func_ea, ref_ea);
		};

		if (!canidates.empty())
		{
			// Sort sig canidates by ascending primarily size, secondarily by 2nd wildcard count
			canidates.sort();

			if (settings.outputLevel >= SETTINGS::LL_VERBOSE)
			{
				msg("\nXfef sig canidates: %u\n", (UINT32) canidates.size());
				for (SIGMATCH &c: canidates)
				{
					qstring str;
					c.sig.ToIdaString(str);
					msg(EAFORMAT ": (%02u, %02u) '%s'\n", c.ea, c.size, c.wildcards, str.c_str());
				}
				msg("\n");
				WaitBox::processIdaEvents();
			}

			// Output the topmost/best canidate
			msg("Function reference ");
			OutputSignature(canidates.front().sig, canidates.front().ea, 0);
			return TRUE;
		}
	}

	// If we made it here, we didn't find a xref sig
	return FALSE;
}

// ------------------------------------------------------------------------------------------------

// Attempt to create unique function signature at selected address
void CreateFunctionSig()
{
    // User selected address
    ea_t ea_selection = get_screen_ea();
    if (ea_selection == BADADDR)
    {
        msg(MSG_TAG "* Select a function address first *\n");
        return;
    }

    // Address must be at or inside a function
    func_t *pfn = get_func(ea_selection);
	if (!pfn)
	{
		msg(MSG_TAG "* Select an address inside a code function *\n");
		return;
	}

    // Convert function into a instruction "siglets" for analysis
	msg("\n");
    msg(MSG_TAG "Finding function signature.\n");
	TIMESTAMP procStart = GetTimestamp();
    SIGLETS siglets;
    if (FuncToSiglets(pfn, siglets))
    {
		if (settings.outputLevel >= SETTINGS::LL_VERBOSE)
		{
			msg("\nFunction siglets:\n");
			DumpFuncSiglets(pfn, siglets);
		}
    }

    // Build a full function signature from the siglets
    SIG funcSig;
    BuildFuncSig(siglets, funcSig);
    if (settings.outputLevel >= SETTINGS::LL_VERBOSE)
    {
        qstring sigStr;
        funcSig.ToIdaString(sigStr);
        msg("\nFull sig: \"%s\"\n\n", sigStr.c_str());
    }
	WaitBox::processIdaEvents();
	WaitBox::show("SigMakerEx", "Working..");
	WaitBox::updateAndCancelCheck(-1);

    // Check if the function is unique first. If it's not, we won't find a unique sig within it
    if (SearchSignature(funcSig) == SSTATUS::UNIQUE)
    {
        LOG_VERBOSE("Function is unqiue, finding optimal settings sig.\n");

        // Find an optimal sig for the unique function
        SIG outsig;
		UINT32 offset = 0;
        ea_t sig_ea = FindFuncSig(pfn, siglets, funcSig, outsig, offset);
		if (sig_ea != BADADDR)
		{
			// If entry point criteria is active, check optional max byte size
			if (settings.funcCriteria == SETTINGS::FUNC_ENTRY_POINT)
			{
				if ((settings.maxEntryPointBytes != 0) && ((UINT32) outsig.bytes.size() > settings.maxEntryPointBytes))
				{
					LOG_VERBOSE("\nEntry point signature byte count exceeds configured max, looking for a reference function sig instead.\n");
					if (!FindFuncXrefSig(pfn->start_ea))
						msg(MSG_TAG "* Failed to find a base or reference signature for selected function. *\n");
					goto exit;
				}
			}

			msg("Function ");
			OutputSignature(outsig, sig_ea, offset);

		}
    }
	else
    // Not unique, look for a function reference signature instead
    {
        LOG_VERBOSE("\nFunction is not unqiue, looking for a reference function sig.\n");
		if (!FindFuncXrefSig(pfn->start_ea))
			msg(MSG_TAG "* Failed to find a base or reference signature for selected function. *\n");
    }

	exit:;
	WaitBox::hide();
    LOG_VERBOSE("Took %.3f seconds.\n", (GetTimestamp() - procStart));
	WaitBox::processIdaEvents();
}


// ------------------------------------------------------------------------------------------------

// Attempt to create unique signature at selected address (inside a function or not)
void CreateAddressSig()
{
	// User selected address
	ea_t ea_selection = get_screen_ea();
	if (ea_selection == BADADDR)
	{
		msg(MSG_TAG "* Select a function address first *\n");
		return;
	}

	msg("\n");
	msg(MSG_TAG "Finding signature for " EAFORMAT ".\n", ea_selection);
	WaitBox::show("SigMakerEx", "Working..");
	WaitBox::updateAndCancelCheck(-1);
	WaitBox::processIdaEvents();
	TIMESTAMP procStart = GetTimestamp();

	// Ideally the address will be inside a function for better instruction analysis. Will typically
	// be the case, but not a requirement here.
	func_t *pfn = get_func(ea_selection);
	if (pfn)
	{
		LOG_VERBOSE("Selected address 0x" EAFORMAT " is inside function 0x" EAFORMAT "\n", ea_selection, pfn->start_ea);

		// Look for a minimal unique sig from address selection down
		SIG sig;
		ea_t sig_ea = FindSigAtFuncAddress(ea_selection, pfn, sig);
		if (sig_ea != BADADDR)
		{
			msg("Address ");
			OutputSignature(sig, ea_selection, 0);
		}
		else
			msg(MSG_TAG "* Failed to find unique signiture at address. *\n");
	}
	else
	{
		// The not inside a function version
		LOG_VERBOSE("Selected address 0x" EAFORMAT " is NOT inside a function.", ea_selection);

		SIG sig;
		ea_t sig_ea = FindSigAtAddress(ea_selection, sig);
		if (sig_ea != BADADDR)
		{
			msg("Address ");
			OutputSignature(sig, ea_selection, 0);
		}
		else
			msg(MSG_TAG "* Failed to find unique signiture at address. *\n");
	}

	WaitBox::hide();
	LOG_VERBOSE("Took %.3f seconds.\n", (GetTimestamp() - procStart));
	WaitBox::processIdaEvents();
}

// ------------------------------------------------------------------------------------------------

void CreateAddressRangeSig()
{
	// Generate signature from user selected address range, unique or not
	ea_t start_ea, end_ea;
	if (read_range_selection(get_current_viewer(), &start_ea, &end_ea))
	{
		if ((end_ea - start_ea) < MIN_SIG_SIZE)
		{
			msg(MSG_TAG "Code selection too small, needs to be at least %u bytes long. *\n", MIN_SIG_SIZE);
			return;
		}

		msg("\n");
		msg(MSG_TAG "Creating signiture from " EAFORMAT " to " EAFORMAT ".\n", start_ea, end_ea);
		WaitBox::processIdaEvents();
		TIMESTAMP procStart = GetTimestamp();

        // Iterate instructions over range.
		SIG sig;
		func_item_iterator_t fIt;
		bool isWithinRange = fIt.set_range(start_ea, end_ea);

        do
        {
            // Add next instruction to signature
            ea_t current_ea = fIt.current();
			SIG siglet;
			int itemSize = InstToSig(get_func(current_ea), current_ea, siglet);
			if (itemSize >= 1)
				sig += siglet;
			else
			{
				// Bail on decode failure, already reported in InstToSig()
				return;
			}

        } while (fIt.next_not_tail());

		if (!sig.bytes.empty())
		{
			sig.trim();
			msg("Range ");
			OutputSignature(sig, start_ea, 0);
		}

		LOG_VERBOSE("Took %.3f seconds.\n", (GetTimestamp() - procStart));
	}
	else
	{
		msg(MSG_TAG "* No code range selected *\n");
	}
	WaitBox::processIdaEvents();
}
