#pragma once

#include <ntifs.h>

enum class SYSTEM_INFORMATION_CLASS :unsigned __int32 {

	SystemProcessInformation = 0x5,
	SystemModuleInformation = 0xb,
	SystemPerformanceTraceInformation = 0x1F
};

struct SYSTEM_THREAD_INFORMATION {
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG ContextSwitches;
	ULONG ThreadState;
	KWAIT_REASON WaitReason;
};

struct SYSTEM_PROCESS_INFORMATION {

	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize;
	ULONG HardFaultCount;
	ULONG NumberOfThreadsHighWatermark;
	ULONGLONG CycleTime;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	ULONG BasePriority;
	HANDLE ProcessId;
	HANDLE InheritedFromProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey;
	ULONG_PTR PeakVirtualSize;
	ULONG_PTR VirtualSize;
	ULONG PageFaultCount;
	ULONG_PTR PeakWorkingSetSize;
	ULONG_PTR WorkingSetSize;
	ULONG_PTR QuotaPeakPagedPoolUsage;
	ULONG_PTR QuotaPagedPoolUsage;
	ULONG_PTR QuotaPeakNonPagedPoolUsage;
	ULONG_PTR QuotaNonPagedPoolUsage;
	ULONG_PTR PagefileUsage;
	ULONG_PTR PeakPagefileUsage;
	ULONG_PTR PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
	SYSTEM_THREAD_INFORMATION Threads[1];
};

extern "C" NTSTATUS ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInfoClass, PVOID SystemInfoBuffer, ULONG SystemInfoBufferSize, PULONG BytesReturned);

inline unsigned __int64* MmPaToVa(unsigned __int64 Pa) {

	PHYSICAL_ADDRESS __Pa{};
	__Pa.QuadPart = Pa;
	return reinterpret_cast<unsigned __int64*>(MmGetVirtualForPhysical(__Pa));
}

inline unsigned __int64 MmVaToPa(void* Va) {

	return static_cast<unsigned __int64>(MmGetPhysicalAddress(Va).QuadPart);
}

inline bool KeMdlCopyMemory(void* TargetAddress, void* SourceAddress, unsigned __int64 SourceLength) {

	MDL* Mdl = IoAllocateMdl(TargetAddress, PAGE_SIZE, false, false, nullptr);
	if (!Mdl) {
		return false;
	}

	MmBuildMdlForNonPagedPool(Mdl);

	void* fAddress = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmNonCached, nullptr, false, NormalPagePriority);
	if (!fAddress) {
		IoFreeMdl(Mdl);
		return false;
	}

	auto Status = MmProtectMdlSystemAddress(Mdl, PAGE_EXECUTE_READWRITE);
	if (NT_ERROR(Status)) {
		MmUnmapLockedPages(fAddress, Mdl);
		IoFreeMdl(Mdl);
		return false;
	}

	KeEnterCriticalRegion();

	_disable();

	RtlMoveMemory(fAddress, SourceAddress, SourceLength);

	_enable();

	KeLeaveCriticalRegion();

	MmUnmapLockedPages(fAddress, Mdl);

	IoFreeMdl(Mdl);

	return true;
}

inline void* KeAllocateContiguousMemorySpecifyCache(SIZE_T NumberOfBytes, MEMORY_CACHING_TYPE CacheType) {

	PHYSICAL_ADDRESS LowestAddress{};

	PHYSICAL_ADDRESS HighestAddress{};
	HighestAddress.QuadPart = MAXULONG64;

	PHYSICAL_ADDRESS BoundaryAddress{};

	return MmAllocateContiguousMemorySpecifyCache(NumberOfBytes, LowestAddress, HighestAddress, BoundaryAddress, CacheType);
}

inline PEPROCESS GetProcessByName(const wchar_t* ProcessName) {

	NTSTATUS Status = 0;
	ULONG bytes = 0;
	PEPROCESS Process = NULL;

	SYSTEM_PROCESS_INFORMATION* ProcessBuffer = NULL;

	Status = ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS::SystemProcessInformation, NULL, 0, &bytes);
	if (Status == STATUS_INFO_LENGTH_MISMATCH) {

		ProcessBuffer = (SYSTEM_PROCESS_INFORMATION*)ExAllocatePool2(POOL_FLAG_NON_PAGED, bytes, 'Mdif');
		if (ProcessBuffer == NULL) {
			return Process;
		}

		RtlZeroMemory(ProcessBuffer, bytes);

		Status = ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS::SystemProcessInformation, ProcessBuffer, bytes, &bytes);
		if (NT_ERROR(Status)) {
			ExFreePoolWithTag(ProcessBuffer, 'Mdif');
			return Process;
		}

		UNICODE_STRING __ProcessName = {};
		RtlInitUnicodeString(&__ProcessName, ProcessName);

		SYSTEM_PROCESS_INFORMATION* __ProcessBuffer = ProcessBuffer;

		for (;;) {

			if (!__ProcessBuffer->NextEntryOffset) {
				break;
			}

			if (!RtlCompareUnicodeString(&__ProcessBuffer->ImageName, &__ProcessName, TRUE)) {

				Status = PsLookupProcessByProcessId(__ProcessBuffer->ProcessId, &Process);
				break;
			}

			__ProcessBuffer =
				reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>((unsigned __int64)__ProcessBuffer + __ProcessBuffer->NextEntryOffset);
		}
	}

	if (ProcessBuffer) {
		ExFreePoolWithTag(ProcessBuffer, 'Mdif');
	}

	return Process;
}