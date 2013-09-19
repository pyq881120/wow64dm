#pragma once

#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <memory>

#include "Internal.h"
#include "Native.h"

namespace ds_wow64
{

class Wow64Local
{
    friend class WoW64dm;

public:
    Wow64Local(void);
    ~Wow64Local(void);

    /*
    */
    DWORD64 X64Call(DWORD64 func, int argC, ...);
    DWORD64 X64Syscall(int idx, int argC, ...);

    /*
    */
    DWORD64 X64CallV(DWORD64 func, int argC, va_list args);
    DWORD64 X64SyscallV(int idx, int argC, va_list args );


    /*
    */
    void memcpy64(DWORD64 /*dst*/, DWORD64 /*src*/, DWORD /*size*/);

    /*
    */
    DWORD64 getTEB64(TEB64& out);

    /*
    */
    DWORD64 GetModuleHandle64( wchar_t* lpModuleName, DWORD* pSize = nullptr );

    /*
    */
    DWORD64 getNTDLL64(DWORD* pSize = nullptr);

    /*
    */
    DWORD64 getLdrGetProcedureAddress();

    /*
    */
    DWORD64 GetProcAddress64( DWORD64 hModule, char* funcName );

    /*
    */
    DWORD64 LoadLibrary64( const wchar_t* path );
private:
    fnNtWow64QIP  _NtWow64QIP;                          // NtWow64QueryInformationProcess64
    fnNtWow64VmOp _NtRPM, _NtWPM;                       // NtWow64WriteVirtualMemory64/fnNtWow64ReadVirtualMemory64

    DWORD64 _ntdll64;                                   // 64bit ntdll address
    DWORD64 _LdrGetProcedureAddress;                    // LdrGetProcedureAddress address in 64bit ntdll
    DWORD   _ntdll64Size;                               // size of ntdll64 image

    DWORD64 ntqvm, ntavm, ntfvm, ntrvm, ntwvm, ntpvm;   // 64bit memory functions (Nt*VirtualMemory)
    DWORD64 gtc, stc;                                   // Get(Set)ThreadContext
};

}