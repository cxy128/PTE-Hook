#include "rewrite.h"

extern "C" char* PsGetProcessImageFileName(PEPROCESS Process);

NTSTATUS fNtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
	ULONG ShareAccess, ULONG OpenOptions) {

	DbgPrintEx(77, 0, "xsubl NtOpenFile ---------------------------------> %s \n", PsGetProcessImageFileName(PsGetCurrentProcess()));

	if (MmIsAddressValid(ObjectAttributes) && MmIsAddressValid(ObjectAttributes->ObjectName) && ObjectAttributes->ObjectName->Length) {

		static UNICODE_STRING RealName = {};
		static UNICODE_STRING FakeName = {};
		if (!RealName.Length || !FakeName.Length) {
			RtlInitUnicodeString(&RealName, L"\\??\\C:\\Users\\15669\\Desktop\\RealName.txt");
			RtlInitUnicodeString(&FakeName, L"\\??\\C:\\Users\\15669\\Desktop\\FakeName.txt");
		}

		if (!RtlCompareUnicodeString(ObjectAttributes->ObjectName, &RealName, TRUE)) {

			UNICODE_STRING* FakeObjectName = nullptr;
			SIZE_T RegionSize = PAGE_SIZE;

			auto Status = ZwAllocateVirtualMemory(ZwCurrentProcess(), reinterpret_cast<void**>(&FakeObjectName), 0, &RegionSize, MEM_COMMIT, PAGE_READWRITE);
			if (NT_SUCCESS(Status) && FakeName.Buffer) {

				RtlZeroMemory(FakeObjectName, RegionSize);

				auto RealObjectName = ObjectAttributes->ObjectName;

				FakeObjectName->Length = FakeName.Length;
				FakeObjectName->MaximumLength = FakeName.MaximumLength;
				FakeObjectName->Buffer = reinterpret_cast<unsigned __int16*>(FakeObjectName + 1);

				RtlCopyMemory(FakeObjectName->Buffer, FakeName.Buffer, FakeName.Length);

				ObjectAttributes->ObjectName = FakeObjectName;

				Status = fNtOpenFileTrampoline(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);

				ObjectAttributes->ObjectName = RealObjectName;

				ZwFreeVirtualMemory(ZwCurrentProcess(), reinterpret_cast<void**>(&FakeObjectName), &RegionSize, MEM_RELEASE);

				return Status;
			}
		}
	}

	return fNtOpenFileTrampoline(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
}

NTSTATUS fNtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
	PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength) {

	DbgPrintEx(77, 0, "xsubl NtCreateFile -------------------------------------------%s \n", PsGetProcessImageFileName(PsGetCurrentProcess()));

	if (MmIsAddressValid(ObjectAttributes) && MmIsAddressValid(ObjectAttributes->ObjectName) && ObjectAttributes->ObjectName->Length) {

		static UNICODE_STRING RealName = {};
		static UNICODE_STRING FakeName = {};
		if (!RealName.Length || !FakeName.Length) {
			RtlInitUnicodeString(&RealName, L"\\??\\C:\\Users\\15669\\Desktop\\RealName.txt");
			RtlInitUnicodeString(&FakeName, L"\\??\\C:\\Users\\15669\\Desktop\\FakeName.txt");
		}

		if (!RtlCompareUnicodeString(ObjectAttributes->ObjectName, &RealName, TRUE)) {

			UNICODE_STRING* FakeObjectName = nullptr;
			SIZE_T RegionSize = PAGE_SIZE;

			auto Status = ZwAllocateVirtualMemory(ZwCurrentProcess(), reinterpret_cast<void**>(&FakeObjectName), 0, &RegionSize, MEM_COMMIT, PAGE_READWRITE);
			if (NT_SUCCESS(Status) && FakeName.Buffer) {

				RtlZeroMemory(FakeObjectName, RegionSize);

				auto RealObjectName = ObjectAttributes->ObjectName;

				FakeObjectName->Length = FakeName.Length;
				FakeObjectName->MaximumLength = FakeName.MaximumLength;
				FakeObjectName->Buffer = reinterpret_cast<unsigned __int16*>(FakeObjectName + 1);

				RtlCopyMemory(FakeObjectName->Buffer, FakeName.Buffer, FakeName.Length);

				ObjectAttributes->ObjectName = FakeObjectName;

				Status = fNtCreateFileTrampoline(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes,
					ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);

				ObjectAttributes->ObjectName = RealObjectName;

				ZwFreeVirtualMemory(ZwCurrentProcess(), reinterpret_cast<void**>(&FakeObjectName), &RegionSize, MEM_RELEASE);

				return Status;
			}
		}
	}

	return fNtCreateFileTrampoline(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition,
		CreateOptions, EaBuffer, EaLength);
}