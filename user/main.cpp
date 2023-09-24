#include <iostream>
#include <Windows.h>
#include <string>
#include <WDBGEXTS.H>

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
    std::shared_ptr<global::Client> client_interface = std::make_shared<global::Client>( thread_pool, pipe_name );

    usermode::UManager umanager( thread_pool, client_interface );
    kernelmode::KManager kmanager( driver_name, thread_pool, client_interface);

    global::headers::SYSTEM_INFORMATION system_information;
    kmanager.SendClientHardwareInformation();

    global::report_structures::SYSTEM_INFORMATION_REQUEST_RESPONSE response;

    client_interface->ServerReceive( &response, sizeof( response ) );

    std::cout << "RequestID: " << response.RequestId << " CanUserProceed: " << 
        response.CanUserProceed << " Reason: " << response.reason << std::endl;

    srand( time( NULL ) );

    while ( !GetAsyncKeyState( VK_DELETE ) )
    {
        //int seed = ( rand() % 7 );

        //std::cout << "Seed: " << seed << std::endl;

        //switch ( seed )
        //{
        //case 0:
        //    kmanager.EnumerateHandleTables();
        //    break;
        //case 1:
        //    kmanager.PerformIntegrityCheck();
        //    break;
        //case 2:
        //    kmanager.ScanPoolsForUnlinkedProcesses();
        //    break;
        //case 3:
        //    kmanager.VerifySystemModules();
        //    break;
        //case 4:
        //    kmanager.ValidateProcessModules();
        //    break;
        //case 5:
        //    kmanager.RunNmiCallbacks();
        //    break;
        //case 6:
        //    kmanager.CheckForAttachedThreads();
        //    break;
        //}
        kmanager.VerifySystemModules();
        kmanager.MonitorCallbackReports();
        std::this_thread::sleep_for( std::chrono::seconds( 10 ) );
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