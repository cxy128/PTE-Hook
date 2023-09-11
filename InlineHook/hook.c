#include <ntifs.h>
#include <intrin.h>
#include "hook.h"

NTSTATUS InlineHook(HANDLE ProcessId, void** KernelAddress, void* OwnAddress, unsigned __int64 BytesNumber) {

	NTSTATUS Status = 0;
	PEPROCESS Process = NULL;
	Status = PsLookupProcessByProcessId(ProcessId, &Process);
	if (NT_ERROR(Status)) {
		return Status;
	}

	KAPC_STATE Apc = {0};
	KeStackAttachProcess(Process, &Apc);

	void* Trampoline = NULL;
	CreateTrampoline(*KernelAddress, BytesNumber, &Trampoline);
	if (Trampoline == NULL) {
		KeUnstackDetachProcess(&Apc);
		ObDereferenceObject(Process);
		return STATUS_NO_MEMORY;
	}

	PAGE_TABLE PageTable = {0};
	PageTable.LinearAddress = PAGE_ALIGN(*KernelAddress);
	GetPageTable(&PageTable);

	unsigned __int64 PdePa = *(unsigned __int64*)PageTable.Pde;

	if (PdePa & 0x80) {

		unsigned __int64* PtVa = SplitLargePage(PdePa);

		if (PtVa != NULL) {
			IsolationPageTable(&PageTable, PtVa);
		}
	}

	unsigned char JmpCode[] = {
		0xFF,0x25,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
	};

	*(void**)&JmpCode[6] = OwnAddress;

	Status = KeMdlCopyMemory(*KernelAddress, JmpCode, sizeof(JmpCode));
	if (NT_ERROR(Status)) {
		KeUnstackDetachProcess(&Apc);
		ObDereferenceObject(Process);
		return Status;
	}

	*KernelAddress = Trampoline;

	KeUnstackDetachProcess(&Apc);
	ObDereferenceObject(Process);

	return Status;
}

NTSTATUS IsolationPageTable(PAGE_TABLE* PageTable, unsigned __int64* PtVa) {

	PHYSICAL_ADDRESS LowestAddress = {0};

	PHYSICAL_ADDRESS HighestAddress = {0};
	HighestAddress.QuadPart = MAXULONG64;

	PHYSICAL_ADDRESS BoundaryAddress = {0};

	unsigned __int64 PageTableMemory = (unsigned __int64)MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE * 3, LowestAddress, HighestAddress, BoundaryAddress, MmCached);
	if (!PageTableMemory) {
		return STATUS_NO_MEMORY;
	}

	RtlSecureZeroMemory((void*)PageTableMemory, PAGE_SIZE * 3);

	unsigned __int64 Cr3 = __readcr3();
	Cr3 = Cr3 & 0x000FFFFFFFFFF000;

	unsigned __int64* Pml4t = MmPaToVa(Cr3);
	unsigned __int64* Pdpt = (unsigned __int64*)(PageTableMemory + 0x0000);
	unsigned __int64* Pdt = (unsigned __int64*)(PageTableMemory + 0x1000);
	unsigned __int64* Pt = PtVa;
	unsigned __int64* Address4kbVa = (unsigned __int64*)(PageTableMemory + 0x2000);

	unsigned __int64 Pml4eIndex = ((unsigned __int64)PageTable->LinearAddress & 0x0000FF8000000000) >> 39;
	unsigned __int64 PdpteIndex = ((unsigned __int64)PageTable->LinearAddress & 0x0000007FC0000000) >> 30;
	unsigned __int64 PdeIndex = ((unsigned __int64)PageTable->LinearAddress & 0x000000003FE00000) >> 21;
	unsigned __int64 PteIndex = ((unsigned __int64)PageTable->LinearAddress & 0x00000000001FF000) >> 12;

	RtlCopyMemory(Pdpt, (unsigned __int64*)(PageTable->Pdpte - PdpteIndex * 8), 0x1000);
	RtlCopyMemory(Pdt, (unsigned __int64*)(PageTable->Pde - PdeIndex * 8), 0x1000);
	RtlCopyMemory(Address4kbVa, PageTable->LinearAddress, 0x1000);

	unsigned __int64 Address4kbPa = MmVaToPa(Address4kbVa);
	unsigned __int64* PteVa = &Pt[PteIndex];
	*PteVa = (*PteVa & 0xFFF0000000000FFF) | (Address4kbPa & 0x000FFFFFFFFFF000);

	unsigned __int64 PtPa = MmVaToPa(Pt);
	unsigned __int64* PdeVa = &Pdt[PdeIndex];
	*PdeVa = (*PdeVa & 0xFFF0000000000FFF) | (PtPa & 0x000FFFFFFFFFF000);
	*PdeVa = *PdeVa & ~0x180;
	*PdeVa = *PdeVa | 0x13;

	unsigned __int64 PdtPa = MmVaToPa(Pdt);
	unsigned __int64* PdpteVa = &Pdpt[PdpteIndex];
	*PdpteVa = (*PdpteVa & 0xFFF0000000000FFF) | (PdtPa & 0x000FFFFFFFFFF000);

	unsigned __int64 PdptPa = MmVaToPa(Pdpt);
	unsigned __int64* Pml4eVa = &Pml4t[Pml4eIndex];
	*Pml4eVa = (*Pml4eVa & 0xFFF0000000000FFF) | (PdptPa & 0x000FFFFFFFFFF000);

	_ReadWriteBarrier();

	__invlpg(Pml4eVa);

	return STATUS_SUCCESS;
}

NTSTATUS CreateTrampoline(void* KernelAddress, unsigned __int64 BytesNumber, void** Trampoline) {

	void* TrampolineBuffer = ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, PAGE_SIZE, 'Tag1');
	if (TrampolineBuffer == NULL) {
		return STATUS_NO_MEMORY;
	}

	RtlZeroMemory(TrampolineBuffer, PAGE_SIZE);

	unsigned char TrampolineCode[] = {
		0x6A,0x00,											// push 0
		0x36,0xC7,0x04,0x24 ,0x00,0x00,0x00,0x00,	 		// mov dword ptr ss : [rsp] , 0x00
		0x36,0xC7,0x44,0x24 ,0x04 ,0x00,0x00,0x00,0x00,		// mov dword ptr ss : [rsp + 4] , 0x00
		0xC3												// ret
	};

	*(unsigned __int32*)&TrampolineCode[6] = (unsigned __int32)(((unsigned __int64)KernelAddress + BytesNumber) & 0xFFFFFFFF);
	*(unsigned __int32*)&TrampolineCode[15] = (unsigned __int32)((((unsigned __int64)KernelAddress + BytesNumber) >> 32) & 0xFFFFFFFF);

	RtlCopyMemory(TrampolineBuffer, KernelAddress, BytesNumber);
	RtlCopyMemory((unsigned __int64*)((unsigned __int64)TrampolineBuffer + BytesNumber), TrampolineCode, sizeof(TrampolineCode));

	*Trampoline = TrampolineBuffer;

	return STATUS_SUCCESS;
}

unsigned __int64* SplitLargePage(unsigned __int64 PdePa) {

	PHYSICAL_ADDRESS LowestAddress = {0};

	PHYSICAL_ADDRESS HighestAddress = {0};
	HighestAddress.QuadPart = MAXULONG64;

	PHYSICAL_ADDRESS BoundaryAddress = {0};

	unsigned __int64* PtVa = MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, LowestAddress, HighestAddress, BoundaryAddress, MmCached);
	if (PtVa == NULL) {
		return NULL;
	}

	RtlSecureZeroMemory(PtVa, PAGE_SIZE);

	unsigned __int64 PtePageFrameNumber = ((PdePa >> 12) << 12) & 0x000FFFFFFFFFF000;

	for (unsigned __int64 i = 0; i < 512; i++) {
		PtVa[i] = PdePa & ~0x100;
		PtVa[i] |= 2;
		PtVa[i] = (PtVa[i] & 0xFFF0000000000FFF) | (PtePageFrameNumber + i * 0x1000);
	}

	return PtVa;
}

// ------------------------------------------------------

unsigned __int64* MmPaToVa(unsigned __int64 Pa) {

	PHYSICAL_ADDRESS _Pa = {0};
	_Pa.QuadPart = Pa;
	return MmGetVirtualForPhysical(_Pa);
}

unsigned __int64 MmVaToPa(unsigned __int64* Va) {

	return MmGetPhysicalAddress(Va).QuadPart;
}

unsigned __int64 GetPageTableBase() {

	static unsigned __int64 PteBase;
	if (PteBase) {
		return PteBase;
	}

	unsigned __int64 Cr3 = __readcr3();
	Cr3 = Cr3 & 0x000FFFFFFFFFF000;

	PHYSICAL_ADDRESS Cr3Pa = {0};
	Cr3Pa.QuadPart = Cr3;
	unsigned __int64* Cr3Va = (unsigned __int64*)MmGetVirtualForPhysical(Cr3Pa);

	for (size_t i = 0; i < 512; i++) {
		if ((Cr3Va[i] & 0x000FFFFFFFFFF000) == Cr3) {
			PteBase = (i << 39) | 0xFFFF000000000000;
			break;
		}
	}

	return PteBase;
}

NTSTATUS KeMdlCopyMemory(void* KernelAddress, void* SourceAddress, unsigned __int64 SourceLength) {

	MDL* Mdl = IoAllocateMdl(KernelAddress, PAGE_SIZE, FALSE, FALSE, NULL);
	if (Mdl == NULL) {
		return STATUS_INVALID_PARAMETER;
	}

	MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);

	void* fAddress = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
	if (fAddress == NULL) {
		IoFreeMdl(Mdl);
		MmUnlockPages(Mdl);
		return STATUS_INVALID_PARAMETER;
	}

	NTSTATUS Status = MmProtectMdlSystemAddress(Mdl, PAGE_EXECUTE_READWRITE);
	if (NT_ERROR(Status)) {
		IoFreeMdl(Mdl);
		MmUnlockPages(Mdl);
		return Status;
	}

	RtlMoveMemory(fAddress, SourceAddress, SourceLength);

	IoFreeMdl(Mdl);
	MmUnlockPages(Mdl);

	return Status;
}

NTSTATUS GetPageTable(PAGE_TABLE* PageTable) {

	unsigned __int64 PteBase = GetPageTableBase();
	if (!PteBase) {
		return STATUS_INVALID_PARAMETER;
	}

	PageTable->Pte = ((((unsigned __int64)PageTable->LinearAddress & 0x0000FFFFFFFFFFFF) >> 12) << 3) + PteBase;
	PageTable->Pde = (((PageTable->Pte & 0x0000FFFFFFFFFFFF) >> 12) << 3) + PteBase;
	PageTable->Pdpte = (((PageTable->Pde & 0x0000FFFFFFFFFFFF) >> 12) << 3) + PteBase;
	PageTable->Pml4e = (((PageTable->Pdpte & 0x0000FFFFFFFFFFFF) >> 12) << 3) + PteBase;

	return STATUS_SUCCESS;
}
