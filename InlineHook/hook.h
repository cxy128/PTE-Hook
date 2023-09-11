#pragma once

typedef struct _PAGE_TABLE {

	unsigned __int64* LinearAddress;
	unsigned __int64 Pte;
	unsigned __int64 Pde;
	unsigned __int64 Pdpte;
	unsigned __int64 Pml4e;

}PAGE_TABLE;

NTSTATUS InlineHook(HANDLE ProcessId, void** KernelAddress, void* OwnAddress, unsigned __int64 BytesNumber);

NTSTATUS CreateTrampoline(void* KernelAddress, unsigned __int64 BytesNumber, void** Trampoline);

NTSTATUS IsolationPageTable(PAGE_TABLE* PageTable, unsigned __int64* PtVa);

unsigned __int64* SplitLargePage(unsigned __int64 PdePa);

unsigned __int64* MmPaToVa(unsigned __int64 Pa);

unsigned __int64 MmVaToPa(unsigned __int64* Va);

unsigned __int64 GetPageTableBase();

NTSTATUS KeMdlCopyMemory(void* KernelAddress, void* SourceAddress, unsigned __int64 SourceLength);

NTSTATUS GetPageTable(PAGE_TABLE* PageTable);

