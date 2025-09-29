
// Common header
#pragma once

#define WIN32_LEAN_AND_MEAN
#define WINVER		 0x0A00 // _WIN32_WINNT_WIN10
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <intrin.h>
#pragma intrinsic(memset, memcpy, memcmp, strcat, strcmp, strcpy, strlen)

// IDA SDK
#define USE_DANGEROUS_FUNCTIONS
#define USE_STANDARD_FILE_FUNCTIONS
//#define NO_OBSOLETE_FUNCS
#pragma warning(push)
#pragma warning(disable:4244) // "conversion from 'ssize_t' to 'int', possible loss of data"
#pragma warning(disable:4267) // "conversion from 'size_t' to 'uint32', possible loss of data"
#pragma warning(disable:4146) // "unary minus operator applied to unsigned type, result still unsigned"
#pragma warning(disable:4018) // warning C4018: '<': signed/unsigned mismatch

#include <ida.hpp>
#include <bytes.hpp>
#include <allins.hpp>
#include <diskio.hpp>
#include <loader.hpp>
#include <search.hpp>
#include <typeinf.hpp>
#pragma warning(pop)

#define MSG_TAG "SigMakerEx: "
#include "Utility.h"

#include "WaitBoxEx.h"

#define MY_VERSION MAKE_SEMANTIC_VERSION(VERSION_RELEASE, 1, 4, 1)
