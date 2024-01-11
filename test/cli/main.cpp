#include <iostream>
#include <string>
#include <vector>
#include <string_view>

#include <Windows.h>
#include <tlhelp32.h>

std::wstring cstr_to_wstr(std::string cstr)
{
        return std::wstring(cstr.begin(), cstr.end());
}

DWORD get_proc_id_by_name(const std::string& process_name)
{
        PROCESSENTRY32 entry = { 0 };
        entry.dwSize = sizeof(PROCESSENTRY32);

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        while (Process32Next(snapshot, &entry))
        {
                if (entry.szExeFile == cstr_to_wstr(process_name))
                {
                        return entry.th32ProcessID;
                }
        }

        CloseHandle(snapshot);

        return 0;
}

int main(int argc, char* argv[])
{
        if (argc < 2)
        {
                std::cerr << "Please enter a valid Process Name";
                return EXIT_FAILURE;
        }

        const std::vector<std::string_view> args(argv + 1, argv + argc);

        std::string process_name = std::string(args[0].data());

        DWORD proc_id = get_proc_id_by_name(process_name);

        if (!proc_id)
        {
                std::cerr << "Process does not exist, please enter a valid running process name." << std::endl;
                return EXIT_FAILURE;
        }



        return EXIT_SUCCESS;
}