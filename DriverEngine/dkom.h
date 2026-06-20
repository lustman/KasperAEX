#pragma once
#include <ntifs.h>
#include <ntddk.h>

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER Reserved;
    HANDLE UniqueProcessId;
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

EXTERN_C NTSTATUS ZwQuerySystemInformation(
    IN ULONG   SystemInformationClass,
    OUT PVOID  SystemInformation,
    IN ULONG   SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

VOID DKOMrootkitDetected();
