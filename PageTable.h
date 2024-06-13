#pragma once

#include "Paging.h"

struct HookMap {

	HANDLE ProcessId;
	UNICODE_STRING SystemRoutineName;
	void* SystemRoutineAddress;
	unsigned __int64 PatchSize;
	char PathBytes[256];
	void* Trampoline;
	unsigned __int64 PdePageFrameNumber;
	unsigned __int64 PtePageFrameNumber;
};

struct HookInformation {

	HookMap* data[1];
	unsigned __int64 Number;
};

inline HookInformation Hooks = {};

bool SetupPageTableHook(HANDLE ProcessId, void* OriginAddress, UNICODE_STRING* SystemRoutineName, void* Handler, void* fTrampoline, unsigned __int64 PatchSize);

bool EnablePageTableHook(HANDLE ProcessId, void* OriginAddress, void* Handler, HookMap* data);

unsigned __int64* CreateTrampoline(unsigned __int64 OriginAddress, unsigned __int64 PatchSize);

bool IsolationPageTable(PAGE_TABLE* PageTable, HookMap* data, PTE* PdeToPt_Va = nullptr);

PTE* SplitLargePage(unsigned __int64 PdeMaps2MBytePageFrameNumber);

void DisablePageTableHook();