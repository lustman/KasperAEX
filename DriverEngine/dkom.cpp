#include "dkom.h"

#define MAX_VISIBLE_PIDS 512
#define SystemProcessInformation 5

static BOOLEAN IsPidVisible(HANDLE Pid, HANDLE* ValidPids, ULONG Count) {
    for (ULONG i = 0; i < Count; i++) {
        if (ValidPids[i] == Pid) {
            return TRUE;
        }
    }
    return FALSE;
}

VOID DKOMrootkitDetected()
{
    ULONG needed = 0;

    ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &needed);
    if (needed == 0) needed = 4096 * 16; 

    PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, needed, 'MOKD');

    if (!buffer) {
        KdPrint(("error;s\n"));
        return;
    }

    NTSTATUS status = ZwQuerySystemInformation(SystemProcessInformation, buffer, needed, &needed);

    HANDLE visiblePids[MAX_VISIBLE_PIDS] = { 0 };
    ULONG visiblePidCount = 0;

    if (NT_SUCCESS(status))
    {
        PSYSTEM_PROCESS_INFORMATION pCurrent = (PSYSTEM_PROCESS_INFORMATION)buffer;
        while (pCurrent != NULL)
        {
            if (visiblePidCount < MAX_VISIBLE_PIDS) {
                visiblePids[visiblePidCount] = pCurrent->UniqueProcessId;
                visiblePidCount++;
            }
            if (pCurrent->NextEntryOffset == 0) break;
            pCurrent = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)pCurrent + pCurrent->NextEntryOffset);
        }
    }

    ExFreePoolWithTag(buffer, 'MOKD');

    ULONG_PTR UniqueProcessIdOffset = 0x440;
    ULONG_PTR ActiveProcessLinksOffset = 0x448;

    PEPROCESS currentEProcess = PsGetCurrentProcess();
    PLIST_ENTRY startNode = (PLIST_ENTRY)((PCHAR)currentEProcess + ActiveProcessLinksOffset);
    PLIST_ENTRY currentNode = startNode->Flink;

    while (currentNode != startNode)
    {
        PEPROCESS eproc = (PEPROCESS)((PCHAR)currentNode - ActiveProcessLinksOffset);
        HANDLE rawPid = *(HANDLE*)((PCHAR)eproc + UniqueProcessIdOffset);

        if (rawPid != (HANDLE)0 && rawPid != (HANDLE)4)
        {
            if (!IsPidVisible(rawPid, visiblePids, visiblePidCount))
            {
                KdPrint(("invisible process detected. dkom pid: %p\n", rawPid));
            }
        }
        currentNode = currentNode->Flink;
    }
}
