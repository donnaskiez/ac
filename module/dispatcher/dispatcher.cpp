#include "dispatcher.h"

#include "../client/message_queue.h"

#include <chrono>

dispatcher::dispatcher::dispatcher(LPCWSTR driver_name, client::message_queue& message_queue) :
    thread_pool(4), k_interface(driver_name, message_queue), u_interface(message_queue)
{
}

void
dispatcher::dispatcher::run()
{
        srand(time(NULL));
        while (true) 
        {
                int seed = (rand() % 11);

                LOG_INFO("seed: %lx", seed);

                switch (seed)
                {
                case 0: k_interface.enumerate_handle_tables(); break;
                case 1: k_interface.perform_integrity_check(); break;
                case 2: k_interface.scan_for_unlinked_processes(); break;
                case 3: k_interface.verify_process_module_executable_regions(); break;
                case 4: k_interface.validate_system_driver_objects(); break;
                case 5: k_interface.run_nmi_callbacks(); break;
                case 6: k_interface.scan_for_attached_threads(); break;
                case 7: k_interface.initiate_apc_stackwalk(); break;
                case 8: k_interface.scan_for_ept_hooks(); break;
                case 9: k_interface.perform_dpc_stackwalk(); break;
                case 10: k_interface.validate_system_modules(); break;
                }
                std::this_thread::sleep_for(std::chrono::seconds(10));
        }
}
