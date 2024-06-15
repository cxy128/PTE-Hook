#include <ntifs.h>
#include <intrin.h>
#include "PageTable.h"
#include "rewrite.h"
#include "util.h"

extern "C" NTSTATUS DriverEntry(DRIVER_OBJECT* DriverObject, UNICODE_STRING*) {

	DriverObject->DriverUnload = [](DRIVER_OBJECT*) -> void {

		KeTerminateProcess();
	};

	auto Process = GetProcessByName(L"sublime_text.exe");
	if (!Process) {
		return STATUS_ACCESS_DENIED;
	}

	auto ProcessId = PsGetProcessId(Process);

	ObDereferenceObject(Process);

	UNICODE_STRING NtOpenFileName{};
	RtlInitUnicodeString(&NtOpenFileName, L"NtOpenFile");
	fNtOpenFileTrampoline = reinterpret_cast<fnNtOpenFile>(MmGetSystemRoutineAddress(&NtOpenFileName));
	if (!SetupPageTableHook(ProcessId, reinterpret_cast<void**>(&fNtOpenFileTrampoline), fNtOpenFile, 17)) {
		return STATUS_ACCESS_DENIED;
	}

	UNICODE_STRING NtCreateFileName{};
	RtlInitUnicodeString(&NtCreateFileName, L"NtCreateFile");
	fNtCreateFileTrampoline = reinterpret_cast<fnNtCreateFile>(MmGetSystemRoutineAddress(&NtCreateFileName));
	if (!SetupPageTableHook(ProcessId, reinterpret_cast<void**>(&fNtCreateFileTrampoline), fNtCreateFile, 14)) {
		return STATUS_ACCESS_DENIED;
	}

	return STATUS_SUCCESS;
};