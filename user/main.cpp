#include <iostream>
#include <Windows.h>
#include <string>
#include <WDBGEXTS.H>

#include "common.h"

#include "threadpool.h"
#include "client.h"

#include "../user/um/umanager.h"
#include "../user/km/kmanager.h"

// BOOLEAN IsTestSigningModeEnabled()
//{
//         ULONG return_length = 0;
//
//         SYSTEM_CODEINTEGRITY_INFORMATION info = { 0 };
//         info.Length = sizeof(SYSTEM_CODEINTEGRITY_INFORMATION);
//         info.CodeIntegrityOptions = 0;
//
//         NTSTATUS status = NtQuerySystemInformation(
//                 SystemCodeIntegrityInformation,
//                 &info,
//                 sizeof(info),
//                 &return_length
//         );
//
//         if (!NT_SUCCESS(status))
//         {
//                 LOG_ERROR("NtQuerySystemInformation failed with status: %lx", status);
//                 return FALSE;
//         }
//
//         return info.CodeIntegrityOptions & CODEINTEGRITY_OPTION_TESTSIGN;
// }

DWORD WINAPI
Init(HINSTANCE hinstDLL)
{
        AllocConsole();
        FILE* file;
        freopen_s(&file, "CONOUT$", "w", stdout);
        freopen_s(&file, "CONIN$", "r", stdin);

        std::this_thread::sleep_for(std::chrono::seconds(1));

        LPTSTR  pipe_name   = (LPTSTR)L"\\\\.\\pipe\\DonnaACPipe";
        LPCWSTR driver_name = L"\\\\.\\DonnaAC";

        std::shared_ptr<global::ThreadPool> thread_pool = std::make_shared<global::ThreadPool>(4);
        std::shared_ptr<global::Client>     client_interface =
            std::make_shared<global::Client>(thread_pool, pipe_name);

        usermode::UManager   umanager(thread_pool, client_interface);
        kernelmode::KManager kmanager(driver_name, thread_pool, client_interface);

        global::headers::SYSTEM_INFORMATION system_information = {0};
        kmanager.SendClientHardwareInformation();

        global::report_structures::SYSTEM_INFORMATION_REQUEST_RESPONSE response = {0};

        // client_interface->ServerReceive( &response, sizeof( response ) );

        // std::cout << "RequestID: " << response.RequestId << " CanUserProceed: " <<
        //     response.CanUserProceed << " Reason: " << response.reason << std::endl;

        /*
         * Note that this is really just for testing the methods for extended periods of time.
         * The "real business logic" would execute the methods with varying degrees of uncertaintity
         * but still allow for bias, i.e we don't want NMI callbacks to be running every 10 seconds.
         * We also need to take into account the performance penalty that some of these routines
         * have, such as the process module validation. At the end of the day an anti cheat that
         * imposes a significant performance pentalty on the game its protecting is useless.
         */

        while (true)
        {
                for (int i = 0; i < 10; i++)
                {
                        kmanager.InsertIrpIntoIrpQueue();
                        Sleep(1000);
                }
        }

        srand(time(NULL));

        while (!GetAsyncKeyState(VK_DELETE))
        {
                int seed = (rand() % 11);

                std::cout << "Seed: " << seed << std::endl;

                switch (seed)
                {
                case 0: kmanager.EnumerateHandleTables(); break;
                case 1: kmanager.PerformIntegrityCheck(); break;
                case 2: kmanager.ScanPoolsForUnlinkedProcesses(); break;
                case 3: kmanager.VerifySystemModuleDriverObjects(); break;
                case 4: kmanager.ValidateProcessModules(); break;
                case 5: kmanager.RunNmiCallbacks(); break;
                case 6: kmanager.CheckForAttachedThreads(); break;
                case 7: kmanager.InitiateApcStackwalkOperation(); break;
                case 8: kmanager.CheckForEptHooks(); break;
                case 9: kmanager.StackwalkThreadsViaDpc(); break;
                case 10: kmanager.ValidateSystemModules(); break;
                }

                kmanager.MonitorCallbackReports();
                std::this_thread::sleep_for(std::chrono::seconds(10));
        }

        fclose(stdout);
        fclose(stdin);
        FreeConsole();

        FreeLibraryAndExitThread(hinstDLL, 0);
        return 0;
}

BOOL WINAPI
DllMain(HINSTANCE hinstDLL,  // handle to DLL module
        DWORD     fdwReason, // reason for calling function
        LPVOID    lpvReserved)  // reserved
{
        // Perform actions based on the reason for calling.
        switch (fdwReason)
        {
        case DLL_PROCESS_ATTACH:

                DisableThreadLibraryCalls(hinstDLL);

                const auto thread = CreateThread(nullptr,
                                                 0,
                                                 reinterpret_cast<LPTHREAD_START_ROUTINE>(Init),
                                                 hinstDLL,
                                                 0,
                                                 nullptr);

                if (thread)
                        CloseHandle(thread);

                break;
        }
        return TRUE; // Successful DLL_PROCESS_ATTACH.
}