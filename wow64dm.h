#pragma once

#define WIN32_LEAN_AND_MEAN

#include <windows.h>

#include "Wow64Local.h"

namespace ds_wow64
{

class WoW64dm
{
public:
    WoW64dm(void);
    ~WoW64dm(void);

    /*
    */
    bool Attach(DWORD pid);

    /*
    */
    void Attach(HANDLE hProcess);

    /*
    */
    DWORD64 getPEB64(PEB64& peb);

    /*
    */
    DWORD64 getTEB64(HANDLE hThread, TEB64& teb);

    /*
    */
    NTSTATUS VirtualQueryEx64(DWORD64 lpAddress, MEMORY_BASIC_INFORMATION64* lpBuffer, DWORD dwLength);

    /*
    */
    NTSTATUS VirtualProtectEx64(DWORD64 lpAddress, DWORD64 dwSize, DWORD flProtect, DWORD* flOld);

    /*
    */
    NTSTATUS VirtualAllocEx64(DWORD64& lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);

    /*
    */
    NTSTATUS VirtualFreeEx64(DWORD64 lpAddress, DWORD dwSize, DWORD dwFreeType);

    /*
    */
    NTSTATUS ReadProcessMemory64(DWORD64 lpBaseAddress, LPVOID lpBuffer, DWORD nSize, DWORD64 *lpNumberOfBytesRead );
    
    /*
    */
    NTSTATUS WriteProcessMemory64(DWORD64 lpBaseAddress, LPVOID lpBuffer, DWORD nSize, DWORD64 *lpNumberOfBytesWritten );

    /*
    */
    NTSTATUS GetThreadContext64(HANDLE hThread, _CONTEXT64* lpContext);

    /*
    */
    NTSTATUS SetThreadContext64(HANDLE hThread, _CONTEXT64* lpContext);

    /*
    */
    DWORD64 GetModuleHandle64( const wchar_t* lpModuleName, DWORD* pSize = nullptr );

    /*
    */
    DWORD64 GetProcAddress64( DWORD64 hModule, DWORD size, const char* funcName );


    /*
    */
    BOOL CreateRemoteThread64( DWORD64 address, DWORD64 arg, bool wait = false );

    /*
    */
    BOOL LoadLibrary64( const wchar_t* path );

    /*
    */
    static Wow64Local& local() { return _local; }

private:
    /*
    */
    BOOL LoadLibraryRemoteWOW64( const wchar_t* path );
    
private:
    HANDLE      _hProcess;
    DWORD       _pid;

    static
    Wow64Local  _local;
};

}


