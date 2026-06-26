#include "PutinShieldTemplate.h"

namespace shield::core 
{
    struct ProcessTokenEntry
    {
        LIST_ENTRY ListEntry;
        HANDLE ProcessId;
        PACCESS_TOKEN OrigToken;
    };

    struct LoadedImageEntry
    {
        LIST_ENTRY ListEntry;
        HANDLE ProcessId;
        PVOID ImageBase;
        SIZE_T ImageSize;
        UNICODE_STRING ImagePath;
    };

     LIST_ENTRY TargetProcessListHead;
     FAST_MUTEX ProcessListMutex;
     LIST_ENTRY LoadedImageListHead;
     FAST_MUTEX ImageListMutex;
     UNICODE_STRING symLinkName;
  

    void handle_process_stop(HANDLE process_id) {
        ExAcquireFastMutex(&ProcessListMutex);
        PLIST_ENTRY link = TargetProcessListHead.Flink;

        while (link != &TargetProcessListHead) {
            auto* entry = CONTAINING_RECORD(link, ProcessTokenEntry, ListEntry);
            if (entry->ProcessId == process_id) {
                RemoveEntryList(link);
                PsDereferencePrimaryToken(entry->OrigToken);
                ExFreePoolWithTag(entry, 'shld');
                KdPrint(("process %p stopped...\n", process_id));
                break; 
            }
            link = link->Flink;
        }
        ExReleaseFastMutex(&ProcessListMutex);
    }
}

NTSTATUS shield::getdriverlist::driverlist(PUNICODE_STRING DriverName, PIMAGE_INFO ImageInfo)
{
    if (!DriverName || !DriverName->Buffer || DriverName->Length == 0 || !ImageInfo)
    {
        return STATUS_SUCCESS;
    }
    KdPrint(("processing driver %wZ at addr %p\n", DriverName, ImageInfo->ImageBase));

    for (ULONG i = 0; i < BLACKLIST_COUNT; i++)
    {
        UNICODE_STRING blacklist;
        RtlInitUnicodeString(&blacklist, BlackListNames[i]);

        if (RtlCompareUnicodeString(DriverName, &blacklist, TRUE) == 0)
        {
            return STATUS_ACCESS_DENIED;
        }
    }
    return STATUS_SUCCESS;
}

void shield::anti_exploit::check_thread_token(HANDLE process_id) {
        PEPROCESS eprocess = nullptr;
        if (NT_SUCCESS(PsLookupProcessByProcessId(process_id, &eprocess))) {
            PACCESS_TOKEN current_token = PsReferencePrimaryToken(eprocess);

            if (current_token != nullptr) {
                ExAcquireFastMutex(&core::ProcessListMutex);

                PLIST_ENTRY link = core::TargetProcessListHead.Flink;
                while (link != &core::TargetProcessListHead) {
                    auto* entry = CONTAINING_RECORD(link, core::ProcessTokenEntry, ListEntry);
                    if (entry->ProcessId == process_id) {
                        if (entry->OrigToken != current_token) {
                            KdPrint(("steal detected pid: %p\n", process_id));
                        }
                        break;
                    }
                    link = link->Flink;
                }
                ExReleaseFastMutex(&core::ProcessListMutex);
                PsDereferencePrimaryToken(current_token);
            }
            ObDereferenceObject(eprocess);
        }
    }

void shield::anti_exploit::save_original_token(HANDLE process_id) {
        PEPROCESS eprocess = nullptr;
        if (NT_SUCCESS(PsLookupProcessByProcessId(process_id, &eprocess))) {
            PACCESS_TOKEN token = PsReferencePrimaryToken(eprocess);
            if (token != nullptr) {
                auto* entry = static_cast<core::ProcessTokenEntry*>(ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(core::ProcessTokenEntry), 'shld'));

                if (entry != nullptr) {
                    entry->ProcessId = process_id;
                    entry->OrigToken = token;

                    ExAcquireFastMutex(&core::ProcessListMutex);
                    InsertTailList(&core::TargetProcessListHead, &entry->ListEntry);
                    ExReleaseFastMutex(&core::ProcessListMutex);
                }
                else {
                    PsDereferencePrimaryToken(token);
                }
            }
            ObDereferenceObject(eprocess);
        }
    }

void shield::monitor::save_loaded_image(PUNICODE_STRING image_name, HANDLE process_id, PIMAGE_INFO image_info) {
        if (!image_name || !image_name->Buffer || image_name->Length == 0 || !image_info) return;

        auto* entry = static_cast<core::LoadedImageEntry*>(ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(core::LoadedImageEntry), 'shld'));
        if (!entry) return;

        entry->ImagePath.Buffer = static_cast<PWCH>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED, image_name->Length, 'strT')
            );
        if (!entry->ImagePath.Buffer) {
            ExFreePoolWithTag(entry, 'shld'); 
            return;
        }

        entry->ProcessId = process_id;
        entry->ImageBase = image_info->ImageBase;
        entry->ImageSize = image_info->ImageSize;
        entry->ImagePath.Length = image_name->Length;
        entry->ImagePath.MaximumLength = image_name->Length;
        RtlCopyMemory(entry->ImagePath.Buffer, image_name->Buffer, image_name->Length);

        ExAcquireFastMutex(&core::ImageListMutex);
        InsertTailList(&core::LoadedImageListHead, &entry->ListEntry);
        ExReleaseFastMutex(&core::ImageListMutex);

        KdPrint(("image saved: PID %p, Path %wZ\n", process_id, &entry->ImagePath));
        shield::getdriverlist::driverlist(image_name, image_info);
}

VOID ThreadNotifyRoutine(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId, _In_ BOOLEAN Create) {
    UNREFERENCED_PARAMETER(ThreadId);
    if (Create) 
    {
        shield::anti_exploit::check_thread_token(ProcessId);
    }
}

VOID ProcessCreateNotifyRoutineEx(IN OUT PEPROCESS Process, IN HANDLE ProcessId, IN OUT PPS_CREATE_NOTIFY_INFO CreateInfo) {
    UNREFERENCED_PARAMETER(Process);
    if (CreateInfo != nullptr) 
    {
        shield::anti_exploit::save_original_token(ProcessId);
    }
    else 
    {
        shield::core::handle_process_stop(ProcessId);
    }
}

VOID ImageLoadNotifyRoutine(_In_ PUNICODE_STRING FullImageName, _In_ HANDLE ProcessId, _In_ PIMAGE_INFO ImageInfo) {
    shield::monitor::save_loaded_image(FullImageName, ProcessId, ImageInfo);
    NTSTATUS getdriver = shield::getdriverlist::driverlist(FullImageName, ImageInfo);
    if (!NT_SUCCESS(getdriver))
    {
        KdPrint(("driver block...\n"));
    }
}


NTSTATUS IRPCREATECLOSE(PDEVICE_OBJECT, PIRP Irp) {
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION ioStack = IoGetCurrentIrpStackLocation(Irp);

    NTSTATUS param = (ioStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_PUTIN_SHIELD_START_PROTECTION ||ioStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_PUTIN_SHIELD_STOP_PROTECTION) ? STATUS_SUCCESS : STATUS_INVALID_DEVICE_REQUEST;

    Irp->IoStatus.Status = param;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return param;
}

void PutinDriverUnload(_In_ PDRIVER_OBJECT DriverObject) {
    PsSetCreateProcessNotifyRoutineEx(ProcessCreateNotifyRoutineEx, TRUE);
    PsRemoveCreateThreadNotifyRoutine(ThreadNotifyRoutine);
    PsRemoveLoadImageNotifyRoutine(ImageLoadNotifyRoutine);

    LARGE_INTEGER interval;
    interval.QuadPart = -10000000; // 1 секунда
    KeDelayExecutionThread(KernelMode, FALSE, &interval);


    ExAcquireFastMutex(&shield::core::ProcessListMutex);
    while (!IsListEmpty(&shield::core::TargetProcessListHead)) {
        PLIST_ENTRY link = RemoveHeadList(&shield::core::TargetProcessListHead);
        auto* entry = CONTAINING_RECORD(link, shield::core::ProcessTokenEntry, ListEntry);

        if (entry->OrigToken != nullptr) {
            PsDereferencePrimaryToken(entry->OrigToken);
        }
        ExFreePoolWithTag(entry, 'shld');
    }
    ExReleaseFastMutex(&shield::core::ProcessListMutex);


    ExAcquireFastMutex(&shield::core::ImageListMutex);
    while (!IsListEmpty(&shield::core::LoadedImageListHead)) {
        PLIST_ENTRY link = RemoveHeadList(&shield::core::LoadedImageListHead);
        auto* entry = CONTAINING_RECORD(link, shield::core::LoadedImageEntry, ListEntry);

        if (entry->ImagePath.Buffer != nullptr) {
            ExFreePoolWithTag(entry->ImagePath.Buffer, 'strT');
        }
        ExFreePoolWithTag(entry, 'shld'); 
    }
    ExReleaseFastMutex(&shield::core::ImageListMutex);

    IoDeleteSymbolicLink(&shield::core::symLinkName);

    if (DriverObject->DeviceObject != nullptr) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }

    KdPrint(("driver unload\n"));
}



extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = PutinDriverUnload;

    UNICODE_STRING deviceName;
    RtlInitUnicodeString(&deviceName, L"\\Device\\PutinShield");

    PDEVICE_OBJECT deviceObject = nullptr;
    NTSTATUS status = IoCreateDevice(DriverObject, sizeof(ULONG), &deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &deviceObject);
    if (!NT_SUCCESS(status)) return status;

    RtlInitUnicodeString(&shield::core::symLinkName, L"\\DosDevices\\PutinShieldLink");
    status = IoCreateSymbolicLink(&shield::core::symLinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(deviceObject);
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = IRPCREATECLOSE;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = IRPCREATECLOSE;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;

    InitializeListHead(&shield::core::TargetProcessListHead);
    ExInitializeFastMutex(&shield::core::ProcessListMutex);
    InitializeListHead(&shield::core::LoadedImageListHead);
    ExInitializeFastMutex(&shield::core::ImageListMutex);

    PsSetCreateProcessNotifyRoutineEx(ProcessCreateNotifyRoutineEx, FALSE);
    PsSetCreateThreadNotifyRoutine(ThreadNotifyRoutine);

    return STATUS_SUCCESS;
}
