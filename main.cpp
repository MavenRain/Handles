// Retrieved and slightly modified from https://forum.sysinternals.com/topic18892.html

#ifndef UNICODE
#define UNICODE
#endif

#include <windows.h>
#include <stdio.h>
#include <memory>

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

class ProcessInformation
{
    void * process;
    void * processDuplicate;
    SYSTEM_HANDLE_INFORMATION * handleInformation;
    OBJECT_TYPE_INFORMATION * typeInformation;
    void * nameInformation;
public:
    ProcessInformation(unsigned long pid, unsigned long handleInformationSize, unsigned long typeInformationSize, unsigned long nameInformationSize)
    : process(OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid))
    , processDuplicate(NULL)
    , handleInformation(static_cast<SYSTEM_HANDLE_INFORMATION *>(malloc(handleInformationSize)))
    , typeInformation(static_cast<OBJECT_TYPE_INFORMATION *>(malloc(typeInformationSize)))
    , nameInformation(malloc(nameInformationSize))
    {}
    void * Process() { return process; }
    void * & ProcessDuplicate() { return processDuplicate; }
    SYSTEM_HANDLE_INFORMATION * & HandleInformation() { return handleInformation; }
    OBJECT_TYPE_INFORMATION * & TypeInformation() { return typeInformation; }
    void * NameInformation() { return nameInformation; }
    void * * AddressOf(HANDLE value) { return & value; }
    template<typename T, typename TPrime>
    TPrime To(T item) { return reinterpret_cast<TPrime>(item); }
    void Resize(unsigned long size) { handleInformation = static_cast<SYSTEM_HANDLE_INFORMATION *>(realloc(handleInformation, size)); }
    ~ProcessInformation()
    {
        free(nameInformation);
        free(typeInformation);
        free(handleInformation);
        if (processDuplicate) CloseHandle(processDuplicate);
        if (process) CloseHandle(process);
    }
};
template<typename T>
struct Result
{
    bool success;
    T result;
    __int64 error;
    Result(T _result) : success(true), result(_result){}
    Result(__int64 _error) : success(false), error(_error){}
    Result(const Result & _result) : success(_result.success), result(_result.result), error(_result.error){}
    ~Result(){}
    T Ok() { return result; }
    __int64 Error() { return error; }
};

static _NtQuerySystemInformation NtQuerySystemInformation(static_cast<_NtQuerySystemInformation>(GetLibraryProcAddress("ntdll.dll", "NtQuerySystemInformation")));
static _NtDuplicateObject NtDuplicateObject(static_cast<_NtDuplicateObject>(GetLibraryProcAddress("ntdll.dll", "NtDuplicateObject")));
static _NtQueryObject NtQueryObject(static_cast<_NtQueryObject>(GetLibraryProcAddress("ntdll.dll", "NtQueryObject")));

Result<ProcessInformation> & GetSystemInformation(Result<ProcessInformation> & processInformation, unsigned long handleInformationSize)
{
    if (! processInformation.success) return processInformation;
    const int systemHandleInformation(16);
    long status(0);
    ProcessInformation processInfo(processInformation.Ok());
    while(1)
    {
        status = NtQuerySystemInformation(systemHandleInformation, processInfo.HandleInformation(), handleInformationSize, NULL);
        if (status != 0xc0000004) break;
        processInfo.Resize(handleInformationSize * 2);
        handleInformationSize *= 2;
    }
    return processInformation;
}

Result<ProcessInformation> & DuplicateHandle(Result<ProcessInformation> & processInformation, void * systemHandle)
{
    if (! processInformation.success) return processInformation;
    ProcessInformation processInfo(processInformation.Ok());
    long status(NtDuplicateObject(processInfo.Process(), systemHandle, GetCurrentProcess(), & processInfo.ProcessDuplicate(), 0, 0, 0) < 0);
    return status < 0 ? Result<ProcessInformation>(status) : processInformation;
}

Result<ProcessInformation> & GetTypeInformation(Result<ProcessInformation> & processInformation, unsigned long typeInformationSize)
{
    if (! processInformation.success) return processInformation;
    ProcessInformation processInfo(processInformation.Ok());
    const int objectTypeInformation(2);
    long status(NtQueryObject(processInfo.ProcessDuplicate(), objectTypeInformation, processInfo.TypeInformation(), typeInformationSize, NULL));
    return status < 0 ? Result<ProcessInformation>(status) : processInformation;
}

Result<ProcessInformation> & GetNameInformation(Result<ProcessInformation> & processInformation, unsigned long nameInformationSize)
{
    if (! processInformation.success) return processInformation;
    ProcessInformation processInfo(processInformation.Ok());
    const int objectNameInformation(1);
    long status(NtQueryObject(processInfo.ProcessDuplicate(), objectNameInformation, processInfo.TypeInformation(), nameInformationSize, NULL));
    return status < 0 ? Result<ProcessInformation>(status) : processInformation;
}

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
    unsigned long handleInfoSize(0x10000);

    if (argc < 2)
    {
        printf("Usage: handles [pid]\n");
        return 1;
    }

    unsigned long pid(_wtoi(argv[1]));
    AutoHandle processHandle(OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid));
    if (! processHandle)
    {
        DWORD lastError(::GetLastError());
        printf(" Could not open PID %d!\nLast Error: %d", pid, lastError);
        return 1;
    }

    Box<SYSTEM_HANDLE_INFORMATION> handleInfo(handleInfoSize);

    // NtQuerySystemInformation won't give us the correct buffer size,
    // so we guess by doubling the buffer size.
    //const int systemHandleInformation(16);
    //long status(0);
    //while(1)
    //{
    //    status = NtQuerySystemInformation(systemHandleInformation, handleInfo, handleInfoSize, NULL);
    //    if (status != 0xc0000004) break;
    //    handleInfo.Resize(handleInfoSize * 2);
    //    handleInfoSize *= 2;
    //}
    //
    //if (status < 0)
    //{
    //    printf("NtQuerySystemInformation failed!\n");
    //    return 1;
    //}
    ProcessInformation processInformation(pid, 0x10000, 0x1000, 0x1000);
    Result<ProcessInformation> systemInformation(GetSystemInformation(Result<ProcessInformation>(processInformation), 0x10000));
    for (ULONG i(0); i < handleInfo->HandleCount; ++ i)
    {
        SYSTEM_HANDLE handle(handleInfo->Handles[i]);
        AutoHandle dupHandle(NULL);
        UNICODE_STRING objectName;
        unsigned long returnLength(0);

        // Check if this handle belongs to the PID the user specified.
        if (handle.ProcessId != pid) continue;

        // Duplicate the handle so we can query it.
        if (NtDuplicateObject(
            processHandle,
            reinterpret_cast<HANDLE>(handle.Handle),
            GetCurrentProcess(),
            dupHandle.Reference(),
            0,
            0,
            0
            ) < 0)
        {
            printf("[%#x] Error!\n", handle.Handle);
            continue;
        }
        Box<OBJECT_TYPE_INFORMATION> objectTypeInfo(0x1000);
        const int objectTypeInformation(2);
        if (NtQueryObject(
            dupHandle,
            objectTypeInformation,
            objectTypeInfo,
            0x1000,
            NULL
            ) < 0)
        {
            printf("[%#x] Error!\n", handle.Handle);
            continue;
        }

        // NtQueryObject hangs on certain Access Masks
        if (handle.GrantedAccess == 0x0012019f || handle.GrantedAccess == 0x120089 || handle.GrantedAccess == 0x120189)
        {
            // We have the type, so display that.
            printf(
                "[%#x] %.*S: (did not get name)\n",
                handle.Handle,
                objectTypeInfo->Name.Length / 2,
                objectTypeInfo->Name.Buffer
                );
            continue;
        }

        Box<void> objectNameInfo(0x1000);
        const int objectNameInformation(1);
        if (NtQueryObject(
            dupHandle,
            objectNameInformation,
            objectNameInfo,
            0x1000,
            & returnLength
            ) < 0)
        {
            // Reallocate the buffer and try again.
            objectNameInfo.Resize(returnLength);
            if (NtQueryObject(
                dupHandle,
                objectNameInformation,
                objectNameInfo,
                returnLength,
                NULL
                ) < 0)
            {
                // We have the type name, so just display that.
                printf(
                    "[%#x] %.*S: (could not get name)\n",
                    handle.Handle,
                    objectTypeInfo->Name.Length / 2,
                    objectTypeInfo->Name.Buffer
                    );
                continue;
            }
        }

        // Cast our buffer into an UNICODE_STRING.
        objectName = * objectNameInfo.To<PUNICODE_STRING>();

        // Print the information!
        if (objectName.Length)
        {
            // The object has a name.
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
            // Print something else.
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
