#include <iostream>
#include <string>
#include <vector>
#include <string_view>

#include <Windows.h>
#include <tlhelp32.h>

DWORD find_process_by_id(int id)
{
        PROCESSENTRY32 entry = { 0 };
        entry.dwSize = sizeof(PROCESSENTRY32);

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        while (Process32Next(snapshot, &entry))
        {
                if (entry.th32ProcessID == id)
                {
                        return entry.th32ProcessID;
                }
        }

        CloseHandle(snapshot);
}

int main(int argc, char* argv[])
{
        if (argc < 2)
        {
                std::cerr << "Please enter a valid Process ID.";
                return EXIT_FAILURE;
        }

        const std::vector<std::string_view> args(argv + 1, argv + argc);

        DWORD id = find_process_by_id(std::stoi(args[0].data()));

        if (!id)
        {
                std::cerr << "Process for the given process ID does not exist" << std::endl;
                return EXIT_FAILURE;
        }

        std::cout << id << std::endl;


        
        return EXIT_SUCCESS;
}