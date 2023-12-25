#include "imports.h"

#include "../common.h"

usermode::Imports::Imports()
{
        NtQueryInformationThread     = nullptr;
        RtlDosPathNameToNtPathName_U = nullptr;

        this->ImportMap["NtQueryInformationThread"]     = NtQueryInformationThread;
        this->ImportMap["RtlDosPathNameToNtPathName_U"] = RtlDosPathNameToNtPathName_U;

        std::map<std::string, void*>::iterator it;

        for (it = this->ImportMap.begin(); it != this->ImportMap.end(); it++)
        {
                HMODULE module_handle = GetModuleHandle(L"ntdll.dll");

                if (!module_handle)
                {
                        LOG_ERROR("GetModuleHandle failed with status code 0x%x", GetLastError());
                        return;
                }

                it->second = GetProcAddress(module_handle, it->first.c_str());

                if (!it->second)
                {
                        LOG_ERROR("GetProcAddress failed with status code 0x%x", GetLastError());
                }
        }
}
