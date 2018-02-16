// Retrieved and slightly modified from https://forum.sysinternals.com/topic18892.html

#ifndef UNICODE
#define UNICODE
#endif

#include <windows.h>
#include <stdio.h>
#include <memory>

#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

typedef NTSTATUS (NTAPI * _NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );
typedef NTSTATUS (NTAPI * _NtDuplicateObject)(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG Attributes,
    ULONG Options
    );
typedef NTSTATUS (NTAPI * _NtQueryObject)(
    HANDLE ObjectHandle,
    ULONG ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
    );

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _SYSTEM_HANDLE
{
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef enum _POOL_TYPE
{
    NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed,
    DontUseThisType,
    NonPagedPoolCacheAligned,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS
} POOL_TYPE, * PPOOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION
{
    UNICODE_STRING Name;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccess;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    USHORT MaintainTypeList;
    POOL_TYPE PoolType;
    ULONG PagedPoolUsage;
    ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

PVOID GetLibraryProcAddress(PSTR LibraryName, PSTR ProcName)
{
    return GetProcAddress(GetModuleHandleA(LibraryName), ProcName);
}

template<typename T>
struct Box
{
    T * item;
    Box(unsigned long size) : item(static_cast<T *>(malloc(size))){}
    operator T *() { return item; }
    T * operator->() { return item; }
    void Resize(unsigned long size) { item = static_cast<T *>(realloc(item, size)); }
    template<typename TPrime>
    TPrime To() { return reinterpret_cast<TPrime>(item); }
    ~Box() { free(item); }
};

int wmain(int argc, WCHAR * argv[])
{
    struct AutoHandle
    {
        HANDLE handle;
        AutoHandle(HANDLE _handle) : handle(_handle){}
        operator HANDLE() { return handle; }
        HANDLE * Reference() { return & handle; }
        ~AutoHandle() { CloseHandle(handle); }
    };
    _NtQuerySystemInformation NtQuerySystemInformation(static_cast<_NtQuerySystemInformation>(GetLibraryProcAddress("ntdll.dll", "NtQuerySystemInformation")));
    _NtDuplicateObject NtDuplicateObject(static_cast<_NtDuplicateObject>(GetLibraryProcAddress("ntdll.dll", "NtDuplicateObject")));
    _NtQueryObject NtQueryObject(static_cast<_NtQueryObject>(GetLibraryProcAddress("ntdll.dll", "NtQueryObject")));
    NTSTATUS status;
    ULONG handleInfoSize(0x10000);

    if (argc < 2)
    {
        printf("Usage: handles [pid]\n");
        return 1;
    }

    ULONG pid(_wtoi(argv[1]));
    AutoHandle processHandle(OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid));
    if (! processHandle)
    {
        printf("Could not open PID %d! (Don't try to open a system process.)\n", pid);
        return 1;
    }

    Box<SYSTEM_HANDLE_INFORMATION> handleInfo(handleInfoSize);

    /* NtQuerySystemInformation won't give us the correct buffer size, 
       so we guess by doubling the buffer size. */
    while ((status = NtQuerySystemInformation(
        SystemHandleInformation,
        handleInfo,
        handleInfoSize,
        NULL
        )) == STATUS_INFO_LENGTH_MISMATCH)
    {
        handleInfo.Resize(handleInfoSize * 2);
        handleInfoSize *= 2;
    }

    /* NtQuerySystemInformation stopped giving us STATUS_INFO_LENGTH_MISMATCH. */
    if (! NT_SUCCESS(status))
    {
        printf("NtQuerySystemInformation failed!\n");
        return 1;
    }
    for (ULONG i(0); i < handleInfo->HandleCount; ++ i)
    {
        SYSTEM_HANDLE handle(handleInfo->Handles[i]);
        AutoHandle dupHandle(NULL);
        UNICODE_STRING objectName;
        ULONG returnLength;

        /* Check if this handle belongs to the PID the user specified. */
        if (handle.ProcessId != pid)
            continue;

        /* Duplicate the handle so we can query it. */
        if (! NT_SUCCESS(NtDuplicateObject(
            processHandle,
            reinterpret_cast<HANDLE>(handle.Handle),
            GetCurrentProcess(),
            dupHandle.Reference(),
            0,
            0,
            0
            )))
        {
            printf("[%#x] Error!\n", handle.Handle);
            continue;
        }

        /* Query the object type. */
        Box<OBJECT_TYPE_INFORMATION> objectTypeInfo(0x1000);
        if (! NT_SUCCESS(NtQueryObject(
            dupHandle,
            ObjectTypeInformation,
            objectTypeInfo,
            0x1000,
            NULL
            )))
        {
            printf("[%#x] Error!\n", handle.Handle);
            continue;
        }

        /* Query the object name (unless it has an access of 
           0x0012019f or 0x00120089, on which NtQueryObject could hang. */
        if (handle.GrantedAccess == 0x0012019f || handle.GrantedAccess == 0x120089)
        {
            /* We have the type, so display that. */
            printf(
                "[%#x] %.*S: (did not get name)\n",
                handle.Handle,
                objectTypeInfo->Name.Length / 2,
                objectTypeInfo->Name.Buffer
                );
            continue;
        }

        Box<void> objectNameInfo(0x1000);
        if (! NT_SUCCESS(NtQueryObject(
            dupHandle,
            ObjectNameInformation,
            objectNameInfo,
            0x1000,
            & returnLength
            )))
        {
            /* Reallocate the buffer and try again. */
            objectNameInfo.Resize(returnLength);
            if (! NT_SUCCESS(NtQueryObject(
                dupHandle,
                ObjectNameInformation,
                objectNameInfo,
                returnLength,
                NULL
                )))
            {
                /* We have the type name, so just display that. */
                printf(
                    "[%#x] %.*S: (could not get name)\n",
                    handle.Handle,
                    objectTypeInfo->Name.Length / 2,
                    objectTypeInfo->Name.Buffer
                    );
                continue;
            }
        }

        /* Cast our buffer into an UNICODE_STRING. */
        objectName = * objectNameInfo.To<PUNICODE_STRING>();

        /* Print the information! */
        if (objectName.Length)
        {
            /* The object has a name. */
            printf(
                "[%#x] %.*S: %.*S\n",
                handle.Handle,
                objectTypeInfo->Name.Length / 2,
                objectTypeInfo->Name.Buffer,
                objectName.Length / 2,
                objectName.Buffer
                );
        }
        else
        {
            /* Print something else. */
            printf(
                "[%#x] %.*S: (unnamed)\n",
                handle.Handle,
                objectTypeInfo->Name.Length / 2,
                objectTypeInfo->Name.Buffer
                );
        }
    }

    return 0;
}
