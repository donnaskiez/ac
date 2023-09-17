#include "symbols.h"

#include <iostream>

static NtSystemDebugControl g_NtSystemDebugControl = NULL;

BOOL
EnablePrivilege(
    _In_ PCWSTR PrivilegeName,
    _In_ BOOLEAN Acquire
)
{
    HANDLE tokenHandle;
    BOOL ret;
    ULONG tokenPrivilegesSize = FIELD_OFFSET( TOKEN_PRIVILEGES, Privileges[ 1 ] );
    PTOKEN_PRIVILEGES tokenPrivileges = static_cast< PTOKEN_PRIVILEGES >( calloc( 1, tokenPrivilegesSize ) );

    if ( tokenPrivileges == NULL )
    {
        return FALSE;
    }

    tokenHandle = NULL;
    tokenPrivileges->PrivilegeCount = 1;
    ret = LookupPrivilegeValue( NULL,
        PrivilegeName,
        &tokenPrivileges->Privileges[ 0 ].Luid );
    if ( ret == FALSE )
    {
        goto Exit;
    }

    tokenPrivileges->Privileges[ 0 ].Attributes = Acquire ? SE_PRIVILEGE_ENABLED
        : SE_PRIVILEGE_REMOVED;

    ret = OpenProcessToken( GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES,
        &tokenHandle );
    if ( ret == FALSE )
    {
        goto Exit;
    }

    ret = AdjustTokenPrivileges( tokenHandle,
        FALSE,
        tokenPrivileges,
        tokenPrivilegesSize,
        NULL,
        NULL );
    if ( ret == FALSE )
    {
        goto Exit;
    }

Exit:
    if ( tokenHandle != NULL )
    {
        CloseHandle( tokenHandle );
    }
    free( tokenPrivileges );
    return ret;
}

HRESULT
CreateDump(
    _In_ PCSTR FilePath
)
{
    HRESULT result;
    HANDLE handle;
    HMODULE module;
    SYSDBG_LIVEDUMP_CONTROL_FLAGS flags;
    SYSDBG_LIVEDUMP_CONTROL_ADDPAGES pages;
    SYSDBG_LIVEDUMP_CONTROL liveDumpControl;
    NTSTATUS status;
    ULONG returnLength;

    handle = INVALID_HANDLE_VALUE;
    result = S_OK;
    flags.AsUlong = 0;
    pages.AsUlong = 0;

    //
    // Get function addresses
    //
    module = LoadLibrary( L"ntdll.dll" );
    if ( module == NULL )
    {
        result = S_FALSE;
        goto Exit;
    }

    g_NtSystemDebugControl = ( NtSystemDebugControl )
        GetProcAddress( module, "NtSystemDebugControl" );

    FreeLibrary( module );

    if ( g_NtSystemDebugControl == NULL )
    {
        result = S_FALSE;
        goto Exit;
    }

    //
    // Get SeDebugPrivilege
    //
    if ( !EnablePrivilege( SE_DEBUG_NAME, TRUE ) )
    {
        result = S_FALSE;
        goto Exit;
    }

    //
    // Create the target file (must specify synchronous I/O)
    //
    handle = CreateFileA( FilePath,
        GENERIC_WRITE | GENERIC_READ,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_FLAG_WRITE_THROUGH | FILE_FLAG_NO_BUFFERING,
        NULL );

    if ( handle == INVALID_HANDLE_VALUE )
    {
        result = S_FALSE;
        goto Exit;
    }

    //
    // Try to create the requested dump
    //
    memset( &liveDumpControl, 0, sizeof( liveDumpControl ) );

    //
    // The only thing the kernel looks at in the struct we pass is the handle,
    // the flags and the pages to dump.
    //
    liveDumpControl.DumpFileHandle = ( PVOID )( handle );
    liveDumpControl.AddPagesControl = pages;
    liveDumpControl.Flags = flags;

    status = g_NtSystemDebugControl( CONTROL_KERNEL_DUMP,
        ( PVOID )( &liveDumpControl ),
        sizeof( liveDumpControl ),
        NULL,
        0,
        &returnLength );

    if ( NT_SUCCESS( status ) )
    {
        result = S_OK;
    }
    else
    {
        result = S_FALSE;
        goto Exit;
    }

Exit:
    if ( handle != INVALID_HANDLE_VALUE )
    {
        CloseHandle( handle );
    }
    return result;
}

VOID GetKernelStructureOffsets( KERNEL_STRUCTURE_OFFSETS* KernelOffsets )
{
    UINT64 kernel_base = NULL;
    HMODULE handle;
    HRESULT result;
    ULONG type_kprocess;
    ULONG type_eprocess;
    ULONG type_kthread;
    ULONG type_ethread;
    DebugCreateFunction dbg_create_function;
    PDEBUG_SYMBOLS symbols = nullptr;
    PDEBUG_DATA_SPACES4 data_spaces = nullptr;
    PDEBUG_CLIENT client = nullptr;
    PDEBUG_CONTROL debug_control = nullptr;
    PCSTR dump_path = "C:\\temp.dmp";

    result = CreateDump( dump_path );

    if ( result != S_OK )
        return;

    handle = GetModuleHandle( L"dbgeng.dll" );

    if ( handle == NULL )
        return;

    dbg_create_function = ( DebugCreateFunction )GetProcAddress( handle, "DebugCreate" );

    if ( dbg_create_function == NULL )
        return;

    result = dbg_create_function( __uuidof( IDebugClient ), ( PVOID* )&client );

    if ( result != S_OK )
        goto end;

    result = client->QueryInterface( __uuidof( IDebugSymbols ), ( PVOID* )&symbols );

    if ( result != S_OK )
        goto end;

    result = client->QueryInterface( __uuidof( IDebugDataSpaces ), ( PVOID* )&data_spaces );

    if ( result != S_OK )
        goto end;

    result = client->QueryInterface( __uuidof( IDebugControl ), ( PVOID* )&debug_control );

    if ( result != S_OK )
        goto end;

    result = client->OpenDumpFile( dump_path );

    result = debug_control->WaitForEvent( DEBUG_WAIT_DEFAULT, INFINITE );

    if ( result != S_OK )
        goto end;



    data_spaces->ReadDebuggerData( DEBUG_DATA_KernBase, &kernel_base, sizeof( UINT64 ), nullptr );

    symbols->GetTypeId( kernel_base, "_KPROCESS", &type_kprocess );
    symbols->GetTypeId( kernel_base, "_EPROCESS", &type_eprocess );
    symbols->GetTypeId( kernel_base, "_KTHREAD", &type_kthread );
    symbols->GetTypeId( kernel_base, "_ETHREAD", &type_ethread );

    symbols->GetFieldOffset( kernel_base, type_kprocess, "ThreadListHead", &KernelOffsets->KPROCESS.thread_list_head );
    symbols->GetFieldOffset( kernel_base, type_kprocess, "DirectoryTableBase", &KernelOffsets->KPROCESS.directory_table_base );

    symbols->GetFieldOffset( kernel_base, type_eprocess, "PeakVirtualSize", &KernelOffsets->EPROCESS.peak_virtual_size );
    symbols->GetFieldOffset( kernel_base, type_eprocess, "VadRoot", &KernelOffsets->EPROCESS.vad_root );
    symbols->GetFieldOffset( kernel_base, type_eprocess, "ObjectTable", &KernelOffsets->EPROCESS.object_table );
    symbols->GetFieldOffset( kernel_base, type_eprocess, "ImageFileName", &KernelOffsets->EPROCESS.image_name );
    symbols->GetFieldOffset( kernel_base, type_eprocess, "Peb", &KernelOffsets->EPROCESS.process_environment_block );

    symbols->GetFieldOffset( kernel_base, type_kthread, "StackBase", &KernelOffsets->KTHREAD.stack_base );
    symbols->GetFieldOffset( kernel_base, type_kthread, "StackLimit", &KernelOffsets->KTHREAD.stack_limit );
    symbols->GetFieldOffset( kernel_base, type_kthread, "ThreadListEntry", &KernelOffsets->KTHREAD.threadlist );
    symbols->GetFieldOffset( kernel_base, type_kthread, "ApcState", &KernelOffsets->KTHREAD.apc_state );
    symbols->GetFieldOffset( kernel_base, type_kthread, "StartAddress", &KernelOffsets->KTHREAD.start_address );

end:

    if ( client != nullptr )
    {
        client->EndSession( DEBUG_END_ACTIVE_DETACH );
        client->Release();
    }

    if ( symbols != nullptr )
        symbols->Release();

    if ( data_spaces != nullptr )
        data_spaces->Release();

    if ( debug_control != nullptr )
        debug_control->Release();
}