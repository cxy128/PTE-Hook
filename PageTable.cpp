#include <ntifs.h>
#include <intrin.h>
#include "PageTable.h"
#include "rewrite.h"
#include "util.h"

bool SetupPageTableHook(HANDLE ProcessId, void** OriginToTrampoline, void* HandlerAddress, unsigned __int64 PatchSize) {

	PEPROCESS Process = nullptr;
	auto Status = PsLookupProcessByProcessId(ProcessId, &Process);
	if (NT_ERROR(Status)) {
		return false;
	}

	Status = KeReplacePageTable(Process, *OriginToTrampoline);
	if (NT_ERROR(Status)) {
		ObDereferenceObject(Process);
		return false;
	}

	auto Trampoline = CreateTrampoline(reinterpret_cast<unsigned __int64>(*OriginToTrampoline), PatchSize);
	if (!Trampoline) {
		ObDereferenceObject(Process);
		return false;
	}

	if (!SetOriginAddressJmpHandlerAddress(Process, *OriginToTrampoline, HandlerAddress)) {
		ObDereferenceObject(Process);
		return false;
	}

	*OriginToTrampoline = Trampoline;

	ObDereferenceObject(Process);

	for (auto i = 0ul; i < __TerminalProcessId.Number; i++) {

		if (__TerminalProcessId.ProcessIdList[i] == ProcessId) {

			return true;
		}
	}

	__TerminalProcessId.ProcessIdList[__TerminalProcessId.Number] = ProcessId;
	__TerminalProcessId.Number += 1;

	return true;
}

bool KeReplacePageTable(PEPROCESS Process, void* OriginAddress) {

	KAPC_STATE Apc{};
	KeStackAttachProcess(Process, &Apc);

	bool IsSuccess = false;

	for (;;) {

		PAGE_TABLE PageTable{};
		PageTable.LinearAddress = reinterpret_cast<unsigned __int64>(PAGE_ALIGN(OriginAddress));
		if (!GetPageTable(&PageTable)) {
			break;
		}

		auto PdePa = *reinterpret_cast<unsigned __int64*>(PageTable.Pde);
		auto PtePa = *reinterpret_cast<unsigned __int64*>(PageTable.Pte);

		if (PdePa & 0x80) {

			auto PtVa = SplitLargePage(PdePa);

			if (!PtVa) {
				break;
			}

			if (!IsolationPageTable(&PageTable, PtVa)) {
				break;
			}

			if (PdePa & 0x100) {
				*reinterpret_cast<unsigned __int64*>(PageTable.Pde) = PdePa & ~0x100;
			}

		} else {

			IsolationPageTable(&PageTable, nullptr);

			if (PtePa & 0x100) {
				*reinterpret_cast<unsigned __int64*>(PageTable.Pte) = PtePa & ~0x100;
			}
		}

		IsSuccess = true;

		break;
	}

	KeUnstackDetachProcess(&Apc);

	return IsSuccess;
}

bool IsolationPageTable(PAGE_TABLE* PageTable, unsigned __int64* PdeToPt_Va) {

	auto PageTableMemory = reinterpret_cast<unsigned __int64>(KeAllocateContiguousMemorySpecifyCache(PAGE_SIZE * 3, MmCached));
	if (!PageTableMemory) {
		return false;
	}

	RtlSecureZeroMemory(reinterpret_cast<unsigned __int64*>(PageTableMemory), PAGE_SIZE * 3);

	auto Cr3 = __readcr3();
	Cr3 = Cr3 & 0x000ffffffffff000;

	unsigned __int64* Pml4tVa = MmPaToVa(Cr3);
	unsigned __int64* PdptVa = reinterpret_cast<unsigned __int64*>(PageTableMemory + 0x0000);
	unsigned __int64* PdtVa = reinterpret_cast<unsigned __int64*>(PageTableMemory + 0x1000);
	unsigned __int64* PtVa = PdeToPt_Va;
	unsigned __int64* Address4kbVa = reinterpret_cast<unsigned __int64*>(PageTableMemory + 0x2000);

	unsigned __int64 Pml4eIndex = (PageTable->LinearAddress & 0x0000FF8000000000) >> 39;
	unsigned __int64 PdpteIndex = (PageTable->LinearAddress & 0x0000007FC0000000) >> 30;
	unsigned __int64 PdeIndex = (PageTable->LinearAddress & 0x000000003FE00000) >> 21;
	unsigned __int64 PteIndex = (PageTable->LinearAddress & 0x00000000001FF000) >> 12;

	RtlCopyMemory(PdptVa, reinterpret_cast<unsigned __int64*>(PageTable->Pdpte - PdpteIndex * 8), PAGE_SIZE);
	RtlCopyMemory(PdtVa, reinterpret_cast<unsigned __int64*>(PageTable->Pde - PdeIndex * 8), PAGE_SIZE);

	if (!PdeToPt_Va) {

		PtVa = reinterpret_cast<unsigned __int64*>(KeAllocateContiguousMemorySpecifyCache(PAGE_SIZE, MmCached));
		if (!PtVa) {
			return false;
		}

		RtlZeroMemory(PtVa, PAGE_SIZE);
		RtlCopyMemory(PtVa, reinterpret_cast<unsigned __int64*>(PageTable->Pte - PteIndex * 8), PAGE_SIZE);
	}

	RtlCopyMemory(Address4kbVa, reinterpret_cast<unsigned __int64*>(PageTable->LinearAddress), PAGE_SIZE);

	KeEnterCriticalRegion();

	_disable();

	unsigned __int64 Address4kbPa = MmVaToPa(Address4kbVa);
	unsigned __int64* PteVa = &PtVa[PteIndex];
	*PteVa = (*PteVa & 0xfff0000000000fff) | (Address4kbPa & 0x000ffffffffff000);

	unsigned __int64 PtPa = MmVaToPa(PtVa);
	unsigned __int64* PdeVa = &PdtVa[PdeIndex];
	*PdeVa = (*PdeVa & 0xfff0000000000fff) | (PtPa & 0x000ffffffffff000);
	*PdeVa = *PdeVa & ~0x780;
	*PdeVa = *PdeVa | 0x13;

	unsigned __int64 PdtPa = MmVaToPa(PdtVa);
	unsigned __int64* PdpteVa = &PdptVa[PdpteIndex];
	*PdpteVa = (*PdpteVa & 0xfff0000000000fff) | (PdtPa & 0x000ffffffffff000);

	unsigned __int64 PdptPa = MmVaToPa(PdptVa);
	unsigned __int64* Pml4eVa = &Pml4tVa[Pml4eIndex];
	*Pml4eVa = (*Pml4eVa & 0xfff0000000000fff) | (PdptPa & 0x000ffffffffff000);

	__invlpg(Pml4eVa);

	_enable();

	KeLeaveCriticalRegion();

	return true;
}

unsigned __int64* SplitLargePage(unsigned __int64 PdePa) {

	auto PtVa = reinterpret_cast<unsigned __int64*>(KeAllocateContiguousMemorySpecifyCache(PAGE_SIZE, MmCached));
	if (!PtVa) {
		return nullptr;
	}

	RtlSecureZeroMemory(PtVa, PAGE_SIZE);

	unsigned __int64 PdePageFrameNumber = ((PdePa >> 12) << 12) & 0x000ffffffffff000;

	for (unsigned __int64 i = 0; i < 512; i++) {
		PtVa[i] = PdePa & ~0x180;
		PtVa[i] = PtVa[i] | 3;
		PtVa[i] = (PtVa[i] & 0xfff0000000000fff) | (PdePageFrameNumber + i * 0x1000);
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

bool SetOriginAddressJmpHandlerAddress(PEPROCESS Process, void* OriginAddress, void* HandlerAddress) {

	KAPC_STATE ApcState{};

	KeStackAttachProcess(Process, &ApcState);

	unsigned char JmpCode[] = {
		0xFF,0x25,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
	};

	*(void**)&JmpCode[6] = HandlerAddress;

	auto R = KeMdlCopyMemory(OriginAddress, JmpCode, sizeof(JmpCode));

	KeUnstackDetachProcess(&ApcState);

	return R;
}

void KeTerminateProcess() {

	for (auto i = 0ul; i < __TerminalProcessId.Number; i++) {

		auto ProcessId = __TerminalProcessId.ProcessIdList[i];

		HANDLE ProcessHandle = nullptr;

		OBJECT_ATTRIBUTES ObjectAttributes{};
		InitializeObjectAttributes(&ObjectAttributes, nullptr, 0, nullptr, nullptr);

		CLIENT_ID ClientId{};
		ClientId.UniqueProcess = ProcessId;

		auto Status = ZwOpenProcess(&ProcessHandle, PROCESS_ALL_ACCESS, &ObjectAttributes, &ClientId);

		if (NT_SUCCESS(Status)) {

			ZwTerminateProcess(ProcessHandle, 0);
		}
	}

	LARGE_INTEGER Interval = {};
	Interval.QuadPart = -10ll * 1000l * 1000l * 2l;
	KeDelayExecutionThread(KernelMode, false, &Interval);
}