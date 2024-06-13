#include <ntifs.h>
#include <intrin.h>
#include "hook.h"
#include "util.h"

using fnNtCreateFile = NTSTATUS(*)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
	PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);

fnNtCreateFile fNtCreateFileTrampoline = nullptr;

NTSTATUS fNtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
	PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength) {

	if (MmIsAddressValid(ObjectAttributes) && MmIsAddressValid(ObjectAttributes->ObjectName) && ObjectAttributes->ObjectName->Length) {

		DbgPrintEx(77, 0, "---> %ls\n", ObjectAttributes->ObjectName->Buffer);

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
				FakeObjectName->Buffer = reinterpret_cast<unsigned __int16*>(FakeObjectName + 3);

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

extern "C" NTSTATUS DriverEntry(DRIVER_OBJECT* DriverObject, PUNICODE_STRING) {

	DriverObject->DriverUnload = [](DRIVER_OBJECT*) -> void {

		for (unsigned __int64 i = 0; i < Hooks.Number; i++) {

			auto item = Hooks.data[i];

			PEPROCESS Process = nullptr;
			auto Status = PsLookupProcessByProcessId(item->ProcessId, &Process);

			if (NT_SUCCESS(Status)) {

				KAPC_STATE ApcState{};
				KeStackAttachProcess(Process, &ApcState);

				KeMdlCopyMemory(item->SystemRoutineAddress, item->PathBytes, item->PatchSize);

				KeUnstackDetachProcess(&ApcState);

				ObDereferenceObject(Process);
			}

			ExFreePoolWithTag(item->Trampoline, '0etP');

			ExFreePoolWithTag(item, '0etP');
		}

	};

	auto Status = STATUS_SUCCESS;

	UNICODE_STRING fName{};
	RtlInitUnicodeString(&fName, L"NtCreateFile");
	auto OriginAddress = MmGetSystemRoutineAddress(&fName);

	auto data = reinterpret_cast<HookMap*>(ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(HookMap), '0etP'));

	if (data) {

		fNtCreateFileTrampoline = reinterpret_cast<fnNtCreateFile>(CreateTrampoline(reinterpret_cast<unsigned __int64>(OriginAddress), 14));

		data->SystemRoutineName = RTL_CONSTANT_STRING(L"NtCreateFile");
		data->PatchSize = 14;
		data->SystemRoutineAddress = OriginAddress;
		data->Trampoline = fNtCreateFileTrampoline;

		RtlCopyMemory(data->PathBytes, OriginAddress, data->PatchSize);

		Hooks.data[Hooks.Number] = data;
		Hooks.Number++;
	}

	SetInlineHook(ULongToHandle(4020), OriginAddress, fNtCreateFile,data);

	return Status;
};