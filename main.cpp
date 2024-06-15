#include <ntifs.h>
#include <intrin.h>
#include "PageTable.h"
#include "rewrite.h"
#include "util.h"

extern "C" NTSTATUS DriverEntry(DRIVER_OBJECT* DriverObject, UNICODE_STRING*) {

	DriverObject->DriverUnload = [](DRIVER_OBJECT*) -> void {

	};

	auto Process = GetProcessByName(L"sublime_text.exe");
	if (!Process) {
		return STATUS_ACCESS_DENIED;
	}

	auto ProcessId = PsGetProcessId(Process);

	ObDereferenceObject(Process);

	UNICODE_STRING NtOpenFileName{};
	RtlInitUnicodeString(&NtOpenFileName, L"NtOpenFile");
	auto NtOpenFileAddress = MmGetSystemRoutineAddress(&NtOpenFileName);

	fNtOpenFileTrampoline = reinterpret_cast<fnNtOpenFile>(CreateTrampoline(reinterpret_cast<unsigned __int64>(NtOpenFileAddress), 17));

	if (!SetupPageTableHook(ProcessId, NtOpenFileAddress, &NtOpenFileName, fNtOpenFile, fNtOpenFileTrampoline, 17)) {
		return STATUS_ACCESS_DENIED;
	}

	UNICODE_STRING NtCreateFileName{};
	RtlInitUnicodeString(&NtCreateFileName, L"NtCreateFile");
	auto NtCreateFileAddress = MmGetSystemRoutineAddress(&NtCreateFileName);

	fNtCreateFileTrampoline = reinterpret_cast<fnNtCreateFile>(CreateTrampoline(reinterpret_cast<unsigned __int64>(NtCreateFileAddress), 14));

	if (!SetupPageTableHook(ProcessId, NtCreateFileAddress, &NtCreateFileName, fNtCreateFile, fNtCreateFileTrampoline, 14)) {
		return STATUS_ACCESS_DENIED;
	}

	return STATUS_SUCCESS;
};