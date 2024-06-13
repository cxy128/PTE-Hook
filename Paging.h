#pragma once

#include <ntifs.h>

struct PML4E {

	union {

		struct {

			unsigned __int64 Present : 1;
			unsigned __int64 ReadWrite : 1;
			unsigned __int64 UserSupervisor : 1;
			unsigned __int64 PageWriteThrough : 1;
			unsigned __int64 PageCacheDisable : 1;
			unsigned __int64 Accessed : 1;
			unsigned __int64 Ignored1 : 1;
			unsigned __int64 PageSize : 1;
			unsigned __int64 Ignored2 : 3;
			unsigned __int64 Ignored3 : 1;
			unsigned __int64 PageFrameNumber : 36;
			unsigned __int64 Reserved : 4;
			unsigned __int64 Ignored4 : 11;
			unsigned __int64 ExecuteDisable : 1;
		};

		unsigned __int64 Value;
	};
};
static_assert(sizeof(PML4E) == sizeof(unsigned __int64), "Size mismatch, only 64-bit supported.");

struct PDPTE {

	union {

		struct {

			unsigned __int64 Present : 1;
			unsigned __int64 ReadWrite : 1;
			unsigned __int64 UserSupervisor : 1;
			unsigned __int64 PageWriteThrough : 1;
			unsigned __int64 PageCacheDisable : 1;
			unsigned __int64 Accessed : 1;
			unsigned __int64 Ignored1 : 1;
			unsigned __int64 PageSize : 1;
			unsigned __int64 Ignored2 : 3;
			unsigned __int64 Ignored3 : 1;
			unsigned __int64 PageFrameNumber : 36;
			unsigned __int64 Reserved : 4;
			unsigned __int64 Ignored4 : 11;
			unsigned __int64 ExecuteDisable : 1;
		};
		unsigned __int64 Value;
	};
};
static_assert(sizeof(PDPTE) == sizeof(unsigned __int64), "Size mismatch, only 64-bit supported.");

struct PDE {

	union {

		struct {

			unsigned __int64 Present : 1;
			unsigned __int64 ReadWrite : 1;
			unsigned __int64 UserSupervisor : 1;
			unsigned __int64 PageWriteThrough : 1;
			unsigned __int64 PageCacheDisable : 1;
			unsigned __int64 Accessed : 1;
			unsigned __int64 Ignored1 : 1;
			unsigned __int64 PageSize : 1;
			unsigned __int64 Ignored2 : 3;
			unsigned __int64 Ignored3 : 1;
			unsigned __int64 PageFrameNumber : 36;
			unsigned __int64 Reserved : 4;
			unsigned __int64 Ignored4 : 11;
			unsigned __int64 ExecuteDisable : 1;
		};
		unsigned __int64 Value;
	};
};
static_assert(sizeof(PDE) == sizeof(unsigned __int64), "Size mismatch, only 64-bit supported.");

struct PTE {

	union {

		struct {
			unsigned __int64 Present : 1;
			unsigned __int64 ReadWrite : 1;
			unsigned __int64 UserSupervisor : 1;
			unsigned __int64 PageWriteThrough : 1;
			unsigned __int64 PageCacheDisable : 1;
			unsigned __int64 Accessed : 1;
			unsigned __int64 Dirty : 1;
			unsigned __int64 PageAccessType : 1;
			unsigned __int64 Global : 1;
			unsigned __int64 Ignored2 : 2;
			unsigned __int64 Ignored3 : 1;
			unsigned __int64 PageFrameNumber : 36;
			unsigned __int64 Reserved : 4;
			unsigned __int64 Ignored4 : 7;
			unsigned __int64 ProtectionKey : 4;
			unsigned __int64 ExecuteDisable : 1;
		};
		unsigned __int64 Value;
	};
};
static_assert(sizeof(PTE) == sizeof(unsigned __int64), "Size mismatch, only 64-bit supported.");

struct PAGE_TABLE {

	unsigned __int64 LinearAddress;
	unsigned __int64 Pte;
	unsigned __int64 Pde;
	unsigned __int64 Pdpte;
	unsigned __int64 Pml4e;

};

inline unsigned __int64 GetPageTableBase() {

	static unsigned __int64 PteBase = 0;
	if (PteBase) {
		return PteBase;
	}

	auto Cr3 = __readcr3();
	Cr3 = Cr3 & 0x000FFFFFFFFFF000;

	PHYSICAL_ADDRESS Cr3Pa = {0};
	Cr3Pa.QuadPart = Cr3;
	auto Cr3Va = reinterpret_cast<unsigned __int64*> (MmGetVirtualForPhysical(Cr3Pa));

	for (size_t i = 0; i < 512; i++) {
		if ((Cr3Va[i] & 0x000FFFFFFFFFF000) == Cr3) {
			PteBase = (i << 39) | 0xFFFF000000000000;
			break;
		}
	}

	return PteBase;
}

inline bool GetPageTable(PAGE_TABLE* PageTable) {

	auto PteBase = GetPageTableBase();
	if (!PteBase) {
		return false;
	}

	PageTable->Pte = (((PageTable->LinearAddress & 0x0000FFFFFFFFFFFF) >> 12) << 3) + PteBase;
	PageTable->Pde = (((PageTable->Pte & 0x0000FFFFFFFFFFFF) >> 12) << 3) + PteBase;
	PageTable->Pdpte = (((PageTable->Pde & 0x0000FFFFFFFFFFFF) >> 12) << 3) + PteBase;
	PageTable->Pml4e = (((PageTable->Pdpte & 0x0000FFFFFFFFFFFF) >> 12) << 3) + PteBase;

	return true;
}

