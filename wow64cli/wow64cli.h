#pragma once
#pragma unmanaged

#include "../wow64dm.h"
#include "NativeEnums.h"

#pragma managed

#include <vcclr.h>

using namespace System;
using namespace System::Runtime::InteropServices;

namespace wow64cli 
{
    [StructLayout(LayoutKind::Sequential, Pack = 8)]
    public ref struct MEMORY_BASIC_INFORMATION64m 
    {
        ULONGLONG BaseAddress;
        ULONGLONG AllocationBase;
        DWORD     AllocationProtect;
        DWORD     __alignment1;
        ULONGLONG RegionSize;
        DWORD     State;
        DWORD     Protect;
        DWORD     Type;
        DWORD     __alignment2;
    };

	public ref class wow64Process
	{
    public:
		wow64Process();
        ~wow64Process();

        /*
        */
        System::Boolean Attach(System::Int32 pid);

        /*
        */
        System::Void Attach(System::IntPtr hProcess);

        /*
        */
        System::UInt32 VirtualQueryEx64(System::UInt64 lpAddress, MEMORY_BASIC_INFORMATION64m^% lpBuffer);

        /*
        */
        System::UInt32 VirtualProtectEx64(System::UInt64 lpAddress, System::UInt64 size, PageProtection flProtect, PageProtection% flOld);

        /*
        */
        System::UInt32 VirtualAllocEx64(System::UInt64% lpAddress, System::Int32 dwSize, AllocType flAllocationType, PageProtection flProtect);

        /*
        */
        System::UInt32 VirtualFreeEx64(System::UInt64 lpAddress, System::Int32 dwSize, AllocType dwFreeType);

        /*
        */
        System::UInt32 ReadProcessMemory64(System::UInt64 lpBaseAddress, array<System::Byte>^% lpBuffer, System::Int32 nSize);
    
        /*
        */
        System::UInt32 WriteProcessMemory64(System::UInt64 lpBaseAddress, array<System::Byte>^% lpBuffer, System::Int32 nSize);

        /*
        */
        //NTSTATUS GetThreadContext64(System::IntPtr hThread, _CONTEXT64* lpContext);

        /*
        */
        //NTSTATUS SetThreadContext64(System::IntPtr hThread, _CONTEXT64* lpContext);

        /*
        */
        System::UInt64 GetModuleHandle64(System::String^ lpModuleName, System::Int32% pSize);

        /*
        */
        System::UInt64 GetProcAddress64(System::UInt64 hModule, System::Int32 size, System::String^ funcName);

        /*
        */
        System::Boolean CreateRemoteThread64(System::UInt64 address, System::UInt64 arg, System::Boolean wait);

        /*
        */
        System::Boolean LoadLibrary64(System::String^ path);

    private:
        ds_wow64::WoW64dm* _native;
	};
}
#pragma unmanaged