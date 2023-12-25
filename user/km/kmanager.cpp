#include "kmanager.h"

kernelmode::KManager::KManager(LPCWSTR                             DriverName,
                               std::shared_ptr<global::ThreadPool> ThreadPool,
                               std::shared_ptr<global::Client>     ReportInterface)
{
        this->driver_interface = std::make_unique<Driver>(DriverName, ReportInterface);
        this->thread_pool      = ThreadPool;
}

void
kernelmode::KManager::RunNmiCallbacks()
{
        this->thread_pool->QueueJob([this]() { this->driver_interface->RunNmiCallbacks(); });
}

void
kernelmode::KManager::VerifySystemModuleDriverObjects()
{
        this->thread_pool->QueueJob(
            [this]() { this->driver_interface->VerifySystemModuleDriverObjects(); });
}

void
kernelmode::KManager::MonitorCallbackReports()
{
        this->thread_pool->QueueJob([this]() { this->driver_interface->QueryReportQueue(); });
}

void
kernelmode::KManager::DetectSystemVirtualization()
{
        this->thread_pool->QueueJob(
            [this]() { this->driver_interface->DetectSystemVirtualization(); });
}

void
kernelmode::KManager::EnumerateHandleTables()
{
        this->thread_pool->QueueJob(
            [this]() { this->driver_interface->CheckHandleTableEntries(); });
}

void
kernelmode::KManager::RequestModuleExecutableRegionsForIntegrityCheck()
{
        this->thread_pool->QueueJob(
            [this]() { this->driver_interface->RequestModuleExecutableRegions(); });
}

VOID
kernelmode::KManager::ScanPoolsForUnlinkedProcesses()
{
        this->thread_pool->QueueJob([this]() { this->driver_interface->ScanForUnlinkedProcess(); });
}

VOID
kernelmode::KManager::PerformIntegrityCheck()
{
        this->thread_pool->QueueJob([this]() { this->driver_interface->PerformIntegrityCheck(); });
}

VOID
kernelmode::KManager::CheckForAttachedThreads()
{
        this->thread_pool->QueueJob(
            [this]() { this->driver_interface->CheckForAttachedThreads(); });
}

VOID
kernelmode::KManager::ValidateProcessModules()
{
        this->thread_pool->QueueJob(
            [this]() { this->driver_interface->VerifyProcessLoadedModuleExecutableRegions(); });
}

VOID
kernelmode::KManager::SendClientHardwareInformation()
{
        this->driver_interface->SendClientHardwareInformation();
}

VOID
kernelmode::KManager::InitiateApcStackwalkOperation()
{
        this->driver_interface->InitiateApcOperation(
            kernelmode::APC_OPERATION_IDS::operation_stackwalk);
}

VOID
kernelmode::KManager::CheckForHiddenThreads()
{
        this->thread_pool->QueueJob([this]() { this->driver_interface->CheckForHiddenThreads(); });
}

VOID
kernelmode::KManager::CheckForEptHooks()
{
        this->thread_pool->QueueJob([this]() { this->driver_interface->CheckForEptHooks(); });
}

VOID
kernelmode::KManager::LaunchIpiInterrupt()
{
        this->thread_pool->QueueJob([this]() { this->driver_interface->LaunchIpiInterrupt(); });
}

VOID
kernelmode::KManager::ValidateSystemModules()
{
        this->thread_pool->QueueJob([this]() { this->driver_interface->ValidateSystemModules(); });
}