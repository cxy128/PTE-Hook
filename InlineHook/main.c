#include <ntifs.h>
#include <intrin.h>
#include "hook.h"

char* PsGetProcessImageFileName(PEPROCESS Process);

typedef NTSTATUS(*fnObpReferenceObjectByHandleWithTag)(
	_In_ HANDLE Handle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_TYPE ObjectType,
	_In_ KPROCESSOR_MODE AccessMode,
	_In_ ULONG Tag,
	_Out_ PVOID* Object,
	_Out_opt_ POBJECT_HANDLE_INFORMATION HandleInformation,
	__int64* WriteHandleInformationSize);

fnObpReferenceObjectByHandleWithTag fObpReferenceObjectByHandleWithTag = NULL;

NTSTATUS HookObpReferenceObjectByHandleWithTag(
	_In_ HANDLE Handle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_TYPE ObjectType,
	_In_ KPROCESSOR_MODE AccessMode,
	_In_ ULONG Tag,
	_Out_ PVOID* Object,
	_Out_opt_ POBJECT_HANDLE_INFORMATION HandleInformation,
	__int64* WriteHandleInformationSize) {

	UNREFERENCED_PARAMETER(DesiredAccess);
	UNREFERENCED_PARAMETER(AccessMode);

	return fObpReferenceObjectByHandleWithTag(Handle, 0, ObjectType, KernelMode, Tag, Object,
		HandleInformation, WriteHandleInformationSize);
}

VOID CreateProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {

	if (CreateInfo != NULL) {

		char* ImageFileName = PsGetProcessImageFileName(Process);
		if (strstr(ImageFileName, "ptepte")) {

			UNICODE_STRING fName = {0};
			RtlInitUnicodeString(&fName, L"ObReferenceObjectByHandleWithTag");
			unsigned char* fObReferenceObjectByHandleWithTag = MmGetSystemRoutineAddress(&fName);

			unsigned __int64 i = 0;
			for (;;) {

				if (fObReferenceObjectByHandleWithTag[i] == (unsigned char)0xE8) {
					i++;
					break;
				}
				i++;
			}

			__int32 Offset = *(__int32*)(fObReferenceObjectByHandleWithTag + i);

			void* __fObpReferenceObjectByHandleWithTag = (void*)(fObReferenceObjectByHandleWithTag + i + 4 + Offset);
			if (fObpReferenceObjectByHandleWithTag == NULL) {
				fObpReferenceObjectByHandleWithTag = (fnObpReferenceObjectByHandleWithTag)__fObpReferenceObjectByHandleWithTag;
				InlineHook(ProcessId, (void**)&fObpReferenceObjectByHandleWithTag, (void*)HookObpReferenceObjectByHandleWithTag, 14);
			} else {
				InlineHook(ProcessId, &__fObpReferenceObjectByHandleWithTag, (void*)HookObpReferenceObjectByHandleWithTag, 14);
			}
		}
	}
}

void DriverUnload(DRIVER_OBJECT* DriverObject) {

	UNREFERENCED_PARAMETER(DriverObject);

	PsSetCreateProcessNotifyRoutineEx(CreateProcessNotify, TRUE);
}

NTSTATUS DriverEntry(DRIVER_OBJECT* DriverObject, PUNICODE_STRING RegistryPath) {

	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS Status = PsSetCreateProcessNotifyRoutineEx(CreateProcessNotify, FALSE);
	UNREFERENCED_PARAMETER(Status);

	return STATUS_SUCCESS;
};