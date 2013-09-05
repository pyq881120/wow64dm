#include "wow64cli.h"

#pragma managed
namespace wow64cli 
{
    wow64Process::wow64Process()
    {
        _native = new ds_wow64::WoW64dm();
    }

    wow64Process::~wow64Process()
    {
        delete _native;
    }

    /*
    */
    System::Boolean wow64Process::Attach( System::Int32 pid )
    {
        return _native->Attach(pid);
    }

    /*
    */
    System::Void wow64Process::Attach( System::IntPtr hProcess )
    {
         return _native->Attach((HANDLE)hProcess);
    }

    System::UInt32 wow64Process::VirtualQueryEx64( System::UInt64 lpAddress, MEMORY_BASIC_INFORMATION64m^% lpBuffer)
    {
        MEMORY_BASIC_INFORMATION64* tmp = new MEMORY_BASIC_INFORMATION64();

        NTSTATUS status = _native->VirtualQueryEx64(lpAddress, tmp, sizeof(MEMORY_BASIC_INFORMATION64));

        lpBuffer = (MEMORY_BASIC_INFORMATION64m^)System::Runtime::InteropServices::Marshal::PtrToStructure(System::IntPtr(tmp), MEMORY_BASIC_INFORMATION64m::typeid);

        delete tmp;
        return status;
    }

    /*
    */
    System::UInt32 wow64Process::VirtualProtectEx64( System::UInt64 lpAddress, System::UInt64 size, PageProtection flProtect, PageProtection% flOld )
    {
        DWORD tmp = 0;
        NTSTATUS status = _native->VirtualProtectEx64(lpAddress, size, (DWORD)flProtect, &tmp);

        flOld = (PageProtection)tmp;
        return status;
    }

    /*
    */
    System::UInt32 wow64Process::VirtualAllocEx64( System::UInt64% lpAddress, System::Int32 dwSize, AllocType flAllocationType, PageProtection flProtect )
    {
        DWORD64 tmp = 0;
        NTSTATUS status = _native->VirtualAllocEx64(tmp, dwSize, (DWORD)flAllocationType, (DWORD)flProtect);

        lpAddress = tmp;
        return status;
    }

    /*
    */
    System::UInt32 wow64Process::VirtualFreeEx64( System::UInt64 lpAddress, System::Int32 dwSize, AllocType dwFreeType )
    {
        return _native->VirtualFreeEx64(lpAddress, dwSize, (DWORD)dwFreeType);
    }

    /*
    */
    System::UInt32 wow64Process::ReadProcessMemory64( System::UInt64 lpBaseAddress, array<System::Byte>^% lpBuffer, System::Int32 nSize )
    {
        pin_ptr<array<System::Byte>^> pPin = &lpBuffer;
        System::IntPtr ptr = System::Runtime::InteropServices::Marshal::UnsafeAddrOfPinnedArrayElement(*pPin, 0);

        return _native->ReadProcessMemory64(lpBaseAddress, (LPVOID)ptr, nSize, 0);
    }

    /*
    */
    System::UInt32 wow64Process::WriteProcessMemory64( System::UInt64 lpBaseAddress, array<System::Byte>^% lpBuffer, System::Int32 nSize )
    {
        pin_ptr<array<System::Byte>^> pPin = &lpBuffer;
        System::IntPtr ptr = System::Runtime::InteropServices::Marshal::UnsafeAddrOfPinnedArrayElement(*pPin, 0);

        return _native->WriteProcessMemory64(lpBaseAddress, (LPVOID)ptr, nSize, 0);
    }

    /*
    */
    System::UInt64 wow64Process::GetModuleHandle64( System::String^ lpModuleName, System::Int32% pSize )
    {
        DWORD size = 0;
        System::IntPtr pStr   = System::Runtime::InteropServices::Marshal::StringToHGlobalUni(lpModuleName);
        System::UInt64 module =  _native->GetModuleHandle64((const wchar_t*)pStr.ToPointer(), &size);

        System::Runtime::InteropServices::Marshal::FreeHGlobal(pStr);
        pSize = size;

        return module;
    }

    /*
    */
    System::UInt64 wow64Process::GetProcAddress64( System::UInt64 hModule, System::Int32 size, System::String^ funcName )
    {
        System::IntPtr pStr = System::Runtime::InteropServices::Marshal::StringToHGlobalAnsi(funcName);
        System::UInt64 proc =  _native->GetProcAddress64(hModule, size, (const char*)pStr.ToPointer());

        System::Runtime::InteropServices::Marshal::FreeHGlobal(pStr);

        return proc;
    }

    /*
    */
    System::Boolean wow64Process::CreateRemoteThread64( System::UInt64 address, System::UInt64 arg, System::Boolean wait )
    {
        return (_native->CreateRemoteThread64(address, arg, wait) == TRUE);
    }

    /*
    */
    System::Boolean wow64Process::LoadLibrary64( System::String^ path )
    {
        System::IntPtr  pStr = System::Runtime::InteropServices::Marshal::StringToHGlobalUni(path);
        System::Boolean res  = (_native->LoadLibrary64((const wchar_t*)pStr.ToPointer()) == TRUE);

        System::Runtime::InteropServices::Marshal::FreeHGlobal(pStr);

        return res;
    }
}
#pragma unmanaged