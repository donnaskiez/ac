#include <iostream>
#include <Windows.h>
#include <string>

#include "common.h"

#include "threadpool.h"
#include "client.h"

#include "../user/um/umanager.h"
#include "../user/km/kmanager.h"

DWORD WINAPI Init(HINSTANCE hinstDLL)
{
    AllocConsole();
    FILE* file;
    freopen_s( &file, "CONOUT$", "w", stdout );
    freopen_s( &file, "CONIN$", "r", stdin );

    std::this_thread::sleep_for( std::chrono::seconds( 1 ) );

    LPTSTR pipe_name = (LPTSTR)L"\\\\.\\pipe\\DonnaACPipe";
    LPCWSTR driver_name = L"\\\\.\\DonnaAC";

    std::shared_ptr<global::ThreadPool> thread_pool = std::make_shared<global::ThreadPool>( 4 );
    std::shared_ptr<global::Client> report_interface = std::make_shared<global::Client>( thread_pool, pipe_name );

    usermode::UManager umanager( thread_pool, report_interface );
    kernelmode::KManager kmanager( driver_name, thread_pool, report_interface);

    while ( !GetAsyncKeyState( VK_DELETE ) )
    {
        kmanager.ValidateProcessModules();

        std::this_thread::sleep_for( std::chrono::milliseconds( 10000 ) );
    }

    fclose( stdout );
    fclose( stdin );
    FreeConsole();

    FreeLibraryAndExitThread( hinstDLL, 0);
    return 0;
}

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpvReserved )  // reserved
{
    // Perform actions based on the reason for calling.
    switch ( fdwReason )
    {
    case DLL_PROCESS_ATTACH:

        DisableThreadLibraryCalls( hinstDLL );

        const auto thread = CreateThread(
            nullptr,
            0,
            reinterpret_cast< LPTHREAD_START_ROUTINE >( Init ),
            hinstDLL,
            0,
            nullptr
        );

        if ( thread )
            CloseHandle( thread );

        break;
    }
    return TRUE;  // Successful DLL_PROCESS_ATTACH.
}