## SigMakerEx

Super IDA Pro signature generator plugin.

### Installation

Copy `IDA_SigMaker32.dLL` and `IDA_SigMaker64.dLL` to your IDA `plugins` directory.

The default IDA hot key is "Ctrl-Alt-S", but can be set to another using key your IDA "plugins.cfg".
Since "Ctrl-Alt-S" now combo conflicts with an IDA default, to avoid getting warning messages, edit your "idagui.cfg" and make the "StackTrace" entry like: `"StackTrace" = 0 // "Ctrl-Alt-S" // open stack trace window` (the '0' disables the key). 

Requires IDA Pro version 7.6'ish.

### Using
Invoke the plugin via its hotkey or via the IDA Edit/Plugin menu.
![main](/images/main.png)

There are three signature generation operations:
 1. **Function**: Used to create a unique function entry point, a minimal function signature w/offset, or a whole-body signature depending on the *Options* config (see below).

    First select any address inside the target function.
    If the selected function is not unique (for the entry point, or the minimal option) then a signature for a unique function cross reference scan will be attempted.

    Typical use cases: Signatures to locate functions at run time in target memory, to locate functions in IDA after executable updates, or to help locate known libraries by signature, etc.


2) **At address**: Attempts to find a unique signature at the selected address.
Typical use case: For locating a particular offset at runtime to hook, or making [Cheat Engine](https://www.cheatengine.org/) script signatures for this purpose, etc.

3. **From address range**: Generates a signature from the selected address range, not checking for uniqueness.
    Special use case for when one of the other actions won't work. Like wanting to ignore the uniqueness of a signature, etc.  

Example signature output:
![minimal_func_example](/images/minimal_func_example.png)

Signature results are pushed to the Windows clipboard for easy CTRL+V pasting into source code, etc.

##### Options
![options](/images/options.png)

**Output format:**
**IDA**: The default hex binary search format that IDA and some other tools support, using spaced hex bytes and "??" wildcards.
Example: `C1 6C E8 ?? ?? ?? ?? 8B 50 08`
**Code style**: Escape coded hex string and a separate mask string where 'x' are keeper bytes, and '?' are wildcard bytes.
Example: `"\xC1\x6C\xE8\xCC\xCC\xCC\xCC\x8B\x50\x08", "xxx????xxx"`
**Inline byte**: A minimalist C style array of bytes with wildcard bytes included format.
Example: `{0xC1,0x6C,0xE8,0xAE,0xAE,0xAE,0xAE,0x8B,0x50,0x08};`
Use the "mask byte" edit box to change the default "Inline byte" mask byte.
The default mask byte is `0xAE`, one of the least used code bytes (see "Ideal mask byte" below).

##### Function sigs: 

The criteria for "Function" signature generation.
**Entry point**: Will attempt to generate a minimal byte sized function entry point signature when possible.
**Minimal byte size**: Will attempt to generate a minimal, with least wildcards count, byte sized (five are greater) instruction boundary aligned signature inside of the selected function body.
**Full function body**: Will attempt to generate a unique full function body signature.

For any of these three options, if the function is not unique, an attempt will be made to locate the smallest unique cross reference signature instead. If you wish to make a full or partial function signature for a non-unique function then use the "From address range" option instead.

**Message level**: Set to "Verbose" for internal signature generation message output to the IDA log window.

**Max function scan refs**: Limit how many function cross references to search when a direct "Function" action signature can't be found. Normally this should be '0' for unlimited search, but for problem cases where there are so many references that causes a slowdown, this can be set to some reasonable limit like 16 or 100.

For the relatively rare case of functions that have their chunks spread over multiple address ranges, the tool will attempt to use just the first chunk. If wishing to make a signature in one of the disjointed chunks, try using the "At address" method. If all else fails, try a "From address range" sig (might take some manual searching for uniqueness).

### Original SigMaker vs SigMakerEx 

1) SigMakerEx ("EX") overall generates smaller and tighter function signatures by using better instruction analysis.
   Example: SigMaker ("SM") wildcards the operand bytes of instruction `sub esp, 90h` (as `"81 EC ?? ?? ?? ??`), throwing out the last four bytes unnecessarily. While EX sees it as an immediate value and keeps the whole `81 EC 90 00 00 00` byte sequence.
2) EX is better focused on normative function body signature use cases.
   For SM there is only one controllable option. It will attempt to make a unique signature at wherever address you select in the function. If it can't find one there, it will look for a unique cross reference sig instead only.
   For EX, since the identified typical use case is to locate function entry points, the smallest entry point signature will be generated when the "Entry point" criteria option is configured.
   For when the "Minimal byte size" option is selected, it will look for the smallest and least wildcard count unique signature (of minimum five bytes) within the whole function body.
3) SM has more output criteria control over byte vs wildcard count, etc., in it's options dialog. EX assumes you want the best of both (least wildcards and smallest byte size).
4) EX omits the "conversion" and the individual "search" functionality that SM has over a preference for a simpler and less cluttered UI.
   
   For searching, since EX always emits IDA format output in addition to the selected output format signatures, use the IDA binary search "Hex" option with the IDA sig string.
4) EX is generally faster, when even doing more extensive searches, due to a technique of cloning the IDB into RAM and using an AVX2 optimized pattern scanner vs relying on the slow IDA find function for scanning.                                                                                                                                                                                                             

### Ideal mask byte

In my own projects for finding patterns dynamically, I prefer the "Inline byte" (for lack of a better name) format.
It's the simplest, most compact, and it doesn't require a runtime transformation from an ASCII hex string.
I've used this format for many projects and have yet to run into any signature collision or redundant match problems.

To minimize potential redundancy issues, it's prudent to use one of the least used code byte values for the wildcard/mask byte. To find the ideal candidates, I gathered the code byte frequency from three each large 32bit and 64bit code segments, then tabulated and sorted the results. The "ida_get_byte_frequency.py" IDA script is used the gather a byte frequency dictionary and save it to a JSON DB. The "byte_frequency_tabulate.py" script tabulates and sorts in ascending order a set of these saved JSON DBs.
It's apparent the byte frequency for 32bit isn't the same as the 64bit one and tabulated independently. See "32bit.txt" and "64bit.txt".
In a visual correlation of the two, 0xA2 is actually the least common denominator, then followed by 0xAE. 
0xAE was chosen over 0xA2 as the default mask byte since its subjectively easier to pick out in hex visually.

### Building

Built using Visual Studio 2019, on Windows 10, with the only dependency being the official IDA Pro C/C++ SDK.
Setup in the project file, it looks for an environment variable `_IDADIR` from which it expects to find a "idasdk/include" and a "idasdk/lib" folder where the IDA SDK is located. Not using `IDADIR` since IDA looks for it itself and can cause a conflict if you try to use more than one installed IDA version.

Python 3.7'ish or better to run the "byte_frequency_tabulate.py" script.

### Credits

Thanks to the creator of the original SigMaker tool back from the gamedeception.net days up to the current C/C++ and Python iteration authors:  P4TR!CK, bobbysing, xero|hawk, ajkhoury, and zoomgod et al.
Thanks to Wojciech Mula for his SIMD programming resources.

### License

Released under MIT © 2022 By Kevin Weatherman
