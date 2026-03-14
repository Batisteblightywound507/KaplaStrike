#include <windows.h>
#include <winternl.h>
#include <winhttp.h>
#include "../draugr/spoof.h"

// KERNEL32 APIs

DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$CreateFileW      ( LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE );
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$CloseHandle      ( HANDLE );
DECLSPEC_IMPORT LPVOID  WINAPI KERNEL32$VirtualAlloc     ( LPVOID, SIZE_T, DWORD, DWORD );
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$VirtualProtect   ( LPVOID, SIZE_T, DWORD, PDWORD );
DECLSPEC_IMPORT BOOLEAN NTAPI  KERNEL32$RtlAddFunctionTable ( PRUNTIME_FUNCTION, DWORD, DWORD64 );
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryA  ( LPCSTR );
WINBASEAPI BOOL WINAPI KERNEL32$VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
DECLSPEC_IMPORT SIZE_T WINAPI KERNEL32$VirtualQuery ( LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T );


// NTDLL APIs

DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtCreateSection    ( PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE );
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtMapViewOfSection ( HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG );
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtClose            ( HANDLE );
DECLSPEC_IMPORT void*    NTAPI NTDLL$memset             ( void*, int, size_t );
DECLSPEC_IMPORT void*    NTAPI NTDLL$memcpy             ( void*, const void*, size_t );

// Hook implementations

HANDLE WINAPI _CreateFileW(
    LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    FUNCTION_CALL call = { 0 };

    call.ptr   = (PVOID)(KERNEL32$CreateFileW);
    call.argc       = 7;
    call.args[0]    = (ULONG_PTR)(lpFileName);
    call.args[1]    = (ULONG_PTR)(dwDesiredAccess);
    call.args[2]    = (ULONG_PTR)(dwShareMode);
    call.args[3]    = (ULONG_PTR)(lpSecurityAttributes);
    call.args[4]    = (ULONG_PTR)(dwCreationDisposition);
    call.args[5]    = (ULONG_PTR)(dwFlagsAndAttributes);
    call.args[6]    = (ULONG_PTR)(hTemplateFile);
    return (HANDLE)spoof_call(&call);
}

BOOL WINAPI _CloseHandle(HANDLE hObject)
{
    FUNCTION_CALL call = { 0 };

    call.ptr   = (PVOID)(KERNEL32$CloseHandle);
    call.argc       = 1;
    call.args[0]    = (ULONG_PTR)(hObject);
    return (BOOL)spoof_call(&call);
}

LPVOID WINAPI _VirtualAlloc(
    LPVOID lpAddress, SIZE_T dwSize,
    DWORD flAllocationType, DWORD flProtect)
{
    FUNCTION_CALL call = { 0 };

    call.ptr   = (PVOID)(KERNEL32$VirtualAlloc);
    call.argc       = 4;
    call.args[0]    = (ULONG_PTR)(lpAddress);
    call.args[1]    = (ULONG_PTR)(dwSize);
    call.args[2]    = (ULONG_PTR)(flAllocationType);
    call.args[3]    = (ULONG_PTR)(flProtect);
    return (LPVOID)spoof_call(&call);
}

BOOL WINAPI _VirtualProtect(
    LPVOID lpAddress, SIZE_T dwSize,
    DWORD flNewProtect, PDWORD lpflOldProtect)
{
    FUNCTION_CALL call = { 0 };

    call.ptr   = (PVOID)(KERNEL32$VirtualProtect);
    call.argc       = 4;
    call.args[0]    = (ULONG_PTR)(lpAddress);
    call.args[1]    = (ULONG_PTR)(dwSize);
    call.args[2]    = (ULONG_PTR)(flNewProtect);
    call.args[3]    = (ULONG_PTR)(lpflOldProtect);
    return (BOOL)spoof_call(&call);
}

BOOLEAN NTAPI _RtlAddFunctionTable(
    PRUNTIME_FUNCTION FunctionTable,
    DWORD EntryCount, DWORD64 BaseAddress)
{
    FUNCTION_CALL call = { 0 };

    call.ptr   = (PVOID)(KERNEL32$RtlAddFunctionTable);
    call.argc       = 3;
    call.args[0]    = (ULONG_PTR)(FunctionTable);
    call.args[1]    = (ULONG_PTR)(EntryCount);
    call.args[2]    = (ULONG_PTR)(BaseAddress);
    return (BOOLEAN)spoof_call(&call);
}

NTSTATUS NTAPI _NtCreateSection(
    PHANDLE SectionHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle)
{
    FUNCTION_CALL call = { 0 };

    call.ptr   = (PVOID)(NTDLL$NtCreateSection);
    call.argc       = 7;
    call.args[0]    = (ULONG_PTR)(SectionHandle);
    call.args[1]    = (ULONG_PTR)(DesiredAccess);
    call.args[2]    = (ULONG_PTR)(ObjectAttributes);
    call.args[3]    = (ULONG_PTR)(MaximumSize);
    call.args[4]    = (ULONG_PTR)(SectionPageProtection);
    call.args[5]    = (ULONG_PTR)(AllocationAttributes);
    call.args[6]    = (ULONG_PTR)(FileHandle);
    return (NTSTATUS)spoof_call(&call);
}

NTSTATUS NTAPI _NtMapViewOfSection(
    HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress,
    ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize, DWORD InheritDisposition,
    ULONG AllocationType, ULONG Win32Protect)
{
    FUNCTION_CALL call = { 0 };

    call.ptr   = (PVOID)(NTDLL$NtMapViewOfSection);
    call.argc       = 10;
    call.args[0]    = (ULONG_PTR)(SectionHandle);
    call.args[1]    = (ULONG_PTR)(ProcessHandle);
    call.args[2]    = (ULONG_PTR)(BaseAddress);
    call.args[3]    = (ULONG_PTR)(ZeroBits);
    call.args[4]    = (ULONG_PTR)(CommitSize);
    call.args[5]    = (ULONG_PTR)(SectionOffset);
    call.args[6]    = (ULONG_PTR)(ViewSize);
    call.args[7]    = (ULONG_PTR)(InheritDisposition);
    call.args[8]    = (ULONG_PTR)(AllocationType);
    call.args[9]    = (ULONG_PTR)(Win32Protect);
    return (NTSTATUS)spoof_call(&call);
}

NTSTATUS NTAPI _NtClose(HANDLE Handle)
{
    FUNCTION_CALL call = { 0 };

    call.ptr   = (PVOID)(NTDLL$NtClose);
    call.argc       = 1;
    call.args[0]    = (ULONG_PTR)(Handle);
    return (NTSTATUS)spoof_call(&call);
}

void* NTAPI _memset(void* dest, int c, size_t count)
{
    FUNCTION_CALL call = { 0 };

    call.ptr   = (PVOID)(NTDLL$memset);
    call.argc       = 3;
    call.args[0]    = (ULONG_PTR)(dest);
    call.args[1]    = (ULONG_PTR)(c);
    call.args[2]    = (ULONG_PTR)(count);
    return (void*)spoof_call(&call);
}

void* NTAPI _memcpy(void* dest, const void* src, size_t count)
{
    FUNCTION_CALL call = { 0 };

    call.ptr   = (PVOID)(NTDLL$memcpy);
    call.argc       = 3;
    call.args[0]    = (ULONG_PTR)(dest);
    call.args[1]    = (ULONG_PTR)(src);
    call.args[2]    = (ULONG_PTR)(count);
    return (void*)spoof_call(&call);
}

HMODULE WINAPI _LoadLibraryA( LPCSTR lpLibFileName )
{
    FUNCTION_CALL call = { 0 };

    call.ptr   = (PVOID)(KERNEL32$LoadLibraryA);
    call.argc       = 1;
    call.args[0]    = (ULONG_PTR)(lpLibFileName);
    return (HMODULE)spoof_call(&call);
}

BOOL WINAPI _VirtualFree(
    LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{
    FUNCTION_CALL call = { 0 };
    call.ptr   = (PVOID)(KERNEL32$VirtualFree);
    call.argc       = 3;
    call.args[0]    = (ULONG_PTR)(lpAddress);
    call.args[1]    = (ULONG_PTR)(dwSize);
    call.args[2]    = (ULONG_PTR)(dwFreeType);
    return (BOOL)spoof_call(&call);
}

SIZE_T WINAPI _VirtualQuery (
    LPCVOID                   lpAddress,
    PMEMORY_BASIC_INFORMATION lpBuffer,
    SIZE_T                    dwLength )
{
    FUNCTION_CALL call = { 0 };

    call.ptr     = ( PVOID ) ( KERNEL32$VirtualQuery );
    call.argc    = 3;
    call.args[0] = ( ULONG_PTR ) ( lpAddress );
    call.args[1] = ( ULONG_PTR ) ( lpBuffer );
    call.args[2] = ( ULONG_PTR ) ( dwLength );

    return ( SIZE_T ) spoof_call ( &call );
}