#pragma once

#include "Paging.h"

struct TerminalProcessId {

	HANDLE ProcessIdList[100];
	unsigned __int32 Number;
	unsigned __int32 MaxNumber = 100;
};

inline TerminalProcessId __TerminalProcessId;

bool SetupPageTableHook(HANDLE ProcessId, void** OriginToTrampoline, void* HandlerAddress, unsigned __int64 PatchSize);

bool KeReplacePageTable(PEPROCESS Process, void* OriginAddress);

bool IsolationPageTable(PAGE_TABLE* PageTable, unsigned __int64* PdeToPt_Va);

unsigned __int64* SplitLargePage(unsigned __int64 PdePa);

unsigned __int64* CreateTrampoline(unsigned __int64 OriginAddress, unsigned __int64 PatchSize);

bool SetOriginAddressJmpHandlerAddress(PEPROCESS Process, void* OriginAddress, void* HandlerAddress);

void KeTerminateProcess();