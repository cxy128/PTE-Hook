#pragma once

#include <ntifs.h>

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

	void* fAddress = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
	if (!fAddress) {
		IoFreeMdl(Mdl);
		return false;
	}

	KeEnterCriticalRegion();

	_disable();

	RtlCopyMemory(fAddress, SourceAddress, SourceLength);

	_enable();

	KeLeaveCriticalRegion();

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