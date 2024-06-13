#pragma once

#include "Paging.h"

bool SetInlineHook(HANDLE ProcessId, void* OriginAddress, void* Handler);

unsigned __int64* CreateTrampoline(unsigned __int64 OriginAddress, unsigned __int64 PatchSize);

bool IsolationPageTable(PAGE_TABLE* PageTable, PTE* PdeToPt_Va = nullptr);

PTE* SplitLargePage(unsigned __int64 PdeMaps2MBytePageFrameNumber);
