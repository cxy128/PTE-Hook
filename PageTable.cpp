#include <ntifs.h>
#include <intrin.h>
#include "PageTable.h"
#include "rewrite.h"
#include "util.h"

bool SetupPageTableHook(HANDLE ProcessId, void* OriginAddress, UNICODE_STRING* SystemRoutineName, void* Handler, void* fTrampoline, unsigned __int64 PatchSize) {

	UNREFERENCED_PARAMETER(SystemRoutineName);

	auto data = reinterpret_cast<HookMap*>(ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(HookMap), '0etP'));
	if (!data) {
		return false;
	}

	RtlZeroMemory(data, sizeof(HookMap));

	data->PatchSize = PatchSize;
	data->SystemRoutineAddress = OriginAddress;
	data->Trampoline = fTrampoline;
	data->ProcessId = ProcessId;

	RtlCopyMemory(data->PathBytes, OriginAddress, data->PatchSize);

	if (!EnablePageTableHook(ProcessId, OriginAddress, Handler, data)) {
		ExFreePoolWithTag(data, '0etP');
		data = nullptr;
		return false;
	}

	return true;
}

bool EnablePageTableHook(HANDLE ProcessId, void* OriginAddress, void* Handler, HookMap* data) {

	PEPROCESS Process = nullptr;
	auto Status = PsLookupProcessByProcessId(ProcessId, &Process);
	if (NT_ERROR(Status)) {
		return false;
	}

	KAPC_STATE Apc{};
	KeStackAttachProcess(Process, &Apc);

	bool IsSuccess = false;

	for (;;) {

		PAGE_TABLE PageTable{};
		PageTable.LinearAddress = reinterpret_cast<unsigned __int64>(PAGE_ALIGN(OriginAddress));
		if (!GetPageTable(&PageTable)) {
			break;
		}

		auto Pde = reinterpret_cast<PDE*>(PageTable.Pde);

		if (Pde->PageSize) {

			bool IsSplitPage = false;

			for (unsigned __int64 i = 0; i < Hooks.Number; i++) {

				auto item = Hooks.data[i];

				if (item && item->PdePageFrameNumber == Pde->PageFrameNumber) {
					IsSplitPage = true;
					break;
				}
			}

			if (!IsSplitPage) {

				auto PtVa = SplitLargePage(Pde->PageFrameNumber);

				if (!PtVa) {
					break;
				}

				if (!IsolationPageTable(&PageTable, data, PtVa)) {
					break;
				}

				Pde->PageSize = 0;

				data->PdePageFrameNumber = Pde->PageFrameNumber;
			}

		} else {

			bool IsIsolationPage = false;
			auto Pte = reinterpret_cast<PTE*>(PageTable.Pte);

			for (unsigned __int64 i = 0; i < Hooks.Number; i++) {

				auto item = Hooks.data[i];

				if (item && Pte->PageFrameNumber == item->PtePageFrameNumber) {
					IsIsolationPage = true;
					break;
				}
			}

			if (!IsIsolationPage && !IsolationPageTable(&PageTable, data)) {
				break;
			}

			data->PtePageFrameNumber = Pte->PageFrameNumber;
		}

		unsigned char JmpCode[] = {
			0xFF,0x25,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
		};

		*(void**)&JmpCode[6] = Handler;

		if (!KeMdlCopyMemory(OriginAddress, JmpCode, sizeof(JmpCode))) {
			break;
		}

		IsSuccess = true;

		Hooks.data[Hooks.Number] = data;
		Hooks.Number++;

		break;
	}

	KeUnstackDetachProcess(&Apc);
	ObDereferenceObject(Process);

	return IsSuccess;
}

bool IsolationPageTable(PAGE_TABLE* PageTable, HookMap* data, PTE* PdeToPt_Va) {

	UNREFERENCED_PARAMETER(data);

	auto PageTableMemory = (unsigned __int64)KeAllocateContiguousMemorySpecifyCache(PAGE_SIZE * 3, MmNonCached);
	if (!PageTableMemory) {
		return false;
	}

	RtlSecureZeroMemory(reinterpret_cast<unsigned __int64*>(PageTableMemory), PAGE_SIZE * 3);

	auto Cr3 = __readcr3();
	Cr3 = Cr3 & 0x000ffffffffff000;

	auto Pml4tVa = reinterpret_cast<PML4E*>(MmPaToVa(Cr3));
	auto PdptVa = reinterpret_cast<PDPTE*>(PageTableMemory + 0x0000);
	auto PdtVa = reinterpret_cast<PDE*>(PageTableMemory + 0x1000);

	PTE* PtVa = nullptr;
	PdeToPt_Va ? PtVa = PdeToPt_Va : PtVa = reinterpret_cast<PTE*>(KeAllocateContiguousMemorySpecifyCache(PAGE_SIZE, MmNonCached));
	if (!PtVa) {
		return false;
	}

	auto Address4kbVa = reinterpret_cast<unsigned __int64*>(PageTableMemory + 0x2000);

	unsigned __int64 Pml4eIndex = (PageTable->LinearAddress & 0x0000FF8000000000) >> 39;
	unsigned __int64 PdpteIndex = (PageTable->LinearAddress & 0x0000007FC0000000) >> 30;
	unsigned __int64 PdeIndex = (PageTable->LinearAddress & 0x000000003FE00000) >> 21;
	unsigned __int64 PteIndex = (PageTable->LinearAddress & 0x00000000001FF000) >> 12;

	RtlCopyMemory(PdptVa, reinterpret_cast<unsigned __int64*>(PageTable->Pdpte - PdpteIndex * 8), PAGE_SIZE);
	RtlCopyMemory(PdtVa, reinterpret_cast<unsigned __int64*>(PageTable->Pde - PdeIndex * 8), PAGE_SIZE);

	if (!PdeToPt_Va) {
		RtlSecureZeroMemory(PtVa, PAGE_SIZE);
		RtlCopyMemory(PtVa, reinterpret_cast<unsigned __int64*>(PageTable->Pte - PteIndex * 8), PAGE_SIZE);
	}

	RtlCopyMemory(Address4kbVa, reinterpret_cast<unsigned __int64*>(PageTable->LinearAddress), PAGE_SIZE);

	KeEnterCriticalRegion();

	_disable();

	auto PteVa = &PtVa[PteIndex];
	PteVa->PageFrameNumber = (MmVaToPa(Address4kbVa) & 0x000FFFFFFFFFF000) >> 12;

	auto PdeVa = &PdtVa[PdeIndex];
	PdeVa->PageFrameNumber = (MmVaToPa(PtVa) & 0x000FFFFFFFFFF000) >> 12;
	PdeVa->PageSize = 0;
	PdeVa->Present = 1;
	PdeVa->ReadWrite = 1;
	PdeVa->PageCacheDisable = 1;

	auto PdpteVa = &PdptVa[PdpteIndex];
	PdpteVa->PageFrameNumber = (MmVaToPa(PdtVa) & 0x000FFFFFFFFFF000) >> 12;

	auto Pml4eVa = &Pml4tVa[Pml4eIndex];
	Pml4eVa->PageFrameNumber = (MmVaToPa(PdptVa) & 0x000FFFFFFFFFF000) >> 12;

	__invlpg(Pml4eVa);

	_enable();

	KeLeaveCriticalRegion();

	return true;
}

PTE* SplitLargePage(unsigned __int64 PdeMaps2MBytePageFrameNumber) {

	auto PtVa = reinterpret_cast<PTE*>(KeAllocateContiguousMemorySpecifyCache(PAGE_SIZE, MmNonCached));
	if (!PtVa) {
		return nullptr;
	}

	RtlSecureZeroMemory(PtVa, PAGE_SIZE);

	unsigned __int64 PtePageFrameNumber = PdeMaps2MBytePageFrameNumber;

	for (unsigned __int64 i = 0; i < 512; i++) {
		(&PtVa[i])->Present = 1;
		(&PtVa[i])->ReadWrite = 1;
		(&PtVa[i])->Global = 0;
		(&PtVa[i])->PageAccessType = 0;
		(&PtVa[i])->PageCacheDisable = 1;
		(&PtVa[i])->UserSupervisor = 1;
		(&PtVa[i])->PageFrameNumber = PtePageFrameNumber + i;
	}

	return PtVa;
}

unsigned __int64* CreateTrampoline(unsigned __int64 OriginAddress, unsigned __int64 PatchSize) {

	auto TrampolineBuffer = reinterpret_cast<unsigned __int8*>(ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, PAGE_SIZE, '0etP'));
	if (!TrampolineBuffer) {
		return nullptr;
	}

	RtlZeroMemory(TrampolineBuffer, PAGE_SIZE);

	unsigned char TrampolineCode[] = {
		0x6A,0x00,											// push 0
		0x36,0xC7,0x04,0x24 ,0x00,0x00,0x00,0x00,	 		// mov dword ptr ss : [rsp] , 0x00
		0x36,0xC7,0x44,0x24 ,0x04 ,0x00,0x00,0x00,0x00,		// mov dword ptr ss : [rsp + 4] , 0x00
		0xC3												// ret
	};

	*(unsigned __int32*)&TrampolineCode[6] = (unsigned __int32)((OriginAddress + PatchSize) & 0xFFFFFFFF);
	*(unsigned __int32*)&TrampolineCode[15] = (unsigned __int32)(((OriginAddress + PatchSize) >> 32) & 0xFFFFFFFF);

	RtlCopyMemory(TrampolineBuffer, reinterpret_cast<unsigned __int64*>(OriginAddress), PatchSize);
	RtlCopyMemory(TrampolineBuffer + PatchSize, TrampolineCode, sizeof(TrampolineCode));

	return reinterpret_cast<unsigned __int64*>(TrampolineBuffer);
}

void DisablePageTableHook() {

	for (unsigned __int64 i = 0; i < Hooks.Number; i++) {

		auto item = Hooks.data[i];
		if (!item) {
			continue;
		}

		PEPROCESS Process = nullptr;
		auto Status = PsLookupProcessByProcessId(item->ProcessId, &Process);

		if (NT_SUCCESS(Status)) {

			KAPC_STATE ApcState{};
			KeStackAttachProcess(Process, &ApcState);

			KeMdlCopyMemory(item->SystemRoutineAddress, item->PathBytes, item->PatchSize);

			KeUnstackDetachProcess(&ApcState);

			ObDereferenceObject(Process);
		}

		item = nullptr;
	}

	Hooks.Number = 0;
}