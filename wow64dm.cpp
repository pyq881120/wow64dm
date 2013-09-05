#include "wow64dm.h"
#include <string>

namespace ds_wow64
{

//
// Gloabals
//
Wow64Local WoW64dm::_local;

WoW64dm::WoW64dm(void) 
    : _hProcess(NULL)
    , _pid(0)
{
    
}

WoW64dm::~WoW64dm(void)
{
    if(_hProcess)
    {
        CloseHandle(_hProcess);
        _hProcess = NULL;
    }
}

/*
*/
bool WoW64dm::Attach( DWORD pid )
{
    // Detach from existing process, if any
    if(_hProcess)
    {
        CloseHandle(_hProcess);

        _hProcess = NULL;
        _pid      = 0;
    }

    _pid = pid;

    if(pid == GetCurrentProcessId())
    {
        _hProcess = GetCurrentProcess();
        return true;
    }
    else
    {
        DWORD dwAccess  = PROCESS_QUERY_INFORMATION | 
                          PROCESS_VM_READ           | 
                          PROCESS_VM_WRITE          | 
                          PROCESS_VM_OPERATION      | 
                          PROCESS_CREATE_THREAD     |
                          PROCESS_SET_QUOTA         |
                          PROCESS_TERMINATE;

        _hProcess = OpenProcess(dwAccess, FALSE, pid);

        return (_hProcess != NULL);
    }
}

void WoW64dm::Attach( HANDLE hProcess )
{
    _hProcess = hProcess;
    _pid      = GetProcessId(hProcess);
}


/*
*/
DWORD64 WoW64dm::getPEB64(PEB64& peb)
{
    _PROCESS_BASIC_INFORMATION_T<DWORD64> info = {0};
    ULONG bytes = 0;

    if(_local._NtWow64QIP != nullptr)
    {
        _local._NtWow64QIP(_hProcess, ProcessBasicInformation, &info, sizeof(info), &bytes);

        if(bytes > 0 && ReadProcessMemory64(info.PebBaseAddress, &peb, sizeof(peb), 0) == STATUS_SUCCESS)
            return info.PebBaseAddress;
    }

    return 0;
}

/*
*/
DWORD64 WoW64dm::getTEB64(HANDLE hThread, TEB64& teb)
{
    _THREAD_BASIC_INFORMATION_T<DWORD64> tbi = {0};
    DWORD64 bytes = 0;

    if(DWORD64 ntqit = _local.GetProcAddress64(_local.getNTDLL64(), "NtQueryInformationThread"))
    {
        if((NTSTATUS)_local.X64Call(ntqit, 6, (DWORD64)hThread, (DWORD64)0, (DWORD64)&tbi, (DWORD64)sizeof(tbi), (DWORD64)&bytes) == STATUS_SUCCESS)
        {
            ReadProcessMemory64(tbi.TebBaseAddress, &teb, sizeof(teb), 0);
            return tbi.TebBaseAddress;
        }
    }

    return 0;
}

/*
*/
NTSTATUS WoW64dm::VirtualQueryEx64( DWORD64 lpAddress, MEMORY_BASIC_INFORMATION64* lpBuffer, DWORD dwLength )
{
    if(_local.ntqvm == 0)
    {
        _local.ntqvm = _local.GetProcAddress64(_local.getNTDLL64(), "NtQueryVirtualMemory");
        if(_local.ntqvm == 0)
            return STATUS_ORDINAL_NOT_FOUND;
    }

    DWORD64 ret = 0;
    return (NTSTATUS)_local.X64Call(_local.ntqvm, 6, (DWORD64)_hProcess, lpAddress, (DWORD64)0, (DWORD64)lpBuffer, (DWORD64)dwLength, (DWORD64)&ret);
}

/*
*/
NTSTATUS WoW64dm::VirtualProtectEx64( DWORD64 lpAddress, DWORD64 dwSize, DWORD flProtect, DWORD* flOld )
{
    if(_local.ntpvm == 0)
    {
        _local.ntpvm = _local.GetProcAddress64(_local.getNTDLL64(), "NtProtectVirtualMemory");
        if(_local.ntpvm == 0)
            return STATUS_ORDINAL_NOT_FOUND;
    }

    return (NTSTATUS)_local.X64Call(_local.ntpvm, 5, (DWORD64)_hProcess, (DWORD64)&lpAddress, (DWORD64)&dwSize, (DWORD64)flProtect, (DWORD64)flOld);
}


/*
*/
NTSTATUS WoW64dm::VirtualAllocEx64( DWORD64& lpAddress, DWORD dwSize, DWORD flAllocationType, DWORD flProtect )
{
    if(_local.ntavm == 0)
    {
        _local.ntavm = _local.GetProcAddress64(_local.getNTDLL64(), "NtAllocateVirtualMemory");
        if(_local.ntavm == 0)
            return STATUS_ORDINAL_NOT_FOUND;
    }

    DWORD64 tmpSize = dwSize;
    return (NTSTATUS)_local.X64Call(_local.ntavm, 6, (DWORD64)_hProcess, (DWORD64)&lpAddress, (DWORD64)0, (DWORD64)&tmpSize, (DWORD64)flAllocationType, (DWORD64)flProtect);
}

/*
*/
NTSTATUS WoW64dm::VirtualFreeEx64( DWORD64 lpAddress, DWORD dwSize, DWORD dwFreeType )
{
    if(_local.ntfvm == 0)
    {
        _local.ntfvm = _local.GetProcAddress64(_local.getNTDLL64(), "NtFreeVirtualMemory");
        if(_local.ntfvm == 0)
            return STATUS_ORDINAL_NOT_FOUND;
    }

    DWORD64 tmpAddr = lpAddress;
    DWORD64 tmpSize = dwSize;

    return (NTSTATUS)_local.X64Call(_local.ntfvm, 4, (DWORD64)_hProcess, (DWORD64)&tmpAddr, (DWORD64)&tmpSize, (DWORD64)dwFreeType);
}

/*
*/
NTSTATUS WoW64dm::ReadProcessMemory64( DWORD64 lpBaseAddress, LPVOID lpBuffer, DWORD nSize, DWORD64 *lpNumberOfBytesRead )
{
    if(_local._NtRPM)
    {
        return  _local._NtRPM(_hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
    }
    else
    {
        if(_local.ntrvm == 0)
        {
            _local.ntrvm = _local.GetProcAddress64(_local.getNTDLL64(), "NtReadVirtualMemory");
            if(_local.ntrvm == 0)
                return STATUS_ORDINAL_NOT_FOUND;
        }

        return (NTSTATUS)_local.X64Call(_local.ntrvm, 5, (DWORD64)_hProcess, lpBaseAddress, (DWORD64)lpBuffer, (DWORD64)nSize, (DWORD64)lpNumberOfBytesRead);
    }
}

/*
*/
NTSTATUS WoW64dm::WriteProcessMemory64( DWORD64 lpBaseAddress, LPVOID lpBuffer, DWORD nSize, DWORD64 *lpNumberOfBytesWritten )
{
    if(_local._NtWPM)
    {
        return _local._NtWPM(_hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
    }
    else
    {
        if(_local.ntwvm == 0)
        {
            _local.ntwvm = _local.GetProcAddress64(_local.getNTDLL64(), "NtWriteVirtualMemory");
            if (_local.ntwvm == 0)
                return STATUS_ORDINAL_NOT_FOUND;
        }

       return (NTSTATUS)_local.X64Call(_local.ntwvm, 5, (DWORD64)_hProcess, lpBaseAddress, (DWORD64)lpBuffer, (DWORD64)nSize, lpNumberOfBytesWritten);
    }
}

/*
*/
NTSTATUS WoW64dm::GetThreadContext64(HANDLE hThread, _CONTEXT64* lpContext)
{
    if(_local.gtc == 0)
    {
        _local.gtc = _local.GetProcAddress64(_local.getNTDLL64(), "NtGetContextThread");
        if(_local.gtc == 0)
            return STATUS_ORDINAL_NOT_FOUND;
    }

    return (NTSTATUS)_local.X64Call(_local.gtc, 2, (DWORD64)hThread, (DWORD64)lpContext);
}

/*
*/
NTSTATUS WoW64dm::SetThreadContext64(HANDLE hThread, _CONTEXT64* lpContext)
{
    if (_local.stc != 0)
    {
        _local.stc = _local.GetProcAddress64(_local.getNTDLL64(), "NtSetContextThread");
        if (_local.stc == 0)
            return STATUS_ORDINAL_NOT_FOUND;
    }

    return (NTSTATUS)_local.X64Call(_local.stc, 2, (DWORD64)hThread, (DWORD64)lpContext);
}

/*
*/
DWORD64 WoW64dm::GetModuleHandle64( const wchar_t* lpModuleName, DWORD* pSize /*= nullptr */ )
{
    DWORD64 module  = 0;
    PEB64 peb = {0};
    PEB_LDR_DATA64 ldr = {0};

    if(getPEB64(peb) != 0 && ReadProcessMemory64(peb.Ldr, &ldr, sizeof(ldr), 0) == STATUS_SUCCESS)
    {
        for(DWORD64 head = ldr.InLoadOrderModuleList.Flink;
            head != (peb.Ldr + FIELD_OFFSET(PEB_LDR_DATA64, InLoadOrderModuleList));
            ReadProcessMemory64((DWORD64)head, &head, sizeof(head), 0))
        {
            wchar_t localbuf[512]            = {0};
            LDR_DATA_TABLE_ENTRY64 localdata = {0};

            ReadProcessMemory64(head, &localdata, sizeof(localdata), 0);
            ReadProcessMemory64(localdata.BaseDllName.Buffer, &localbuf, localdata.BaseDllName.Length, 0);

            if (_wcsicmp(localbuf, lpModuleName) == 0)
            {
                module = localdata.DllBase;
                if(pSize)
                    *pSize = localdata.SizeOfImage;

                break;
            }
        }
    }

    return module;
}


/*
*/
DWORD64 WoW64dm::GetProcAddress64( DWORD64 hModule, DWORD size, const char* funcName )
{
    if(hModule == 0 || size == 0)
        return 0;

    std::unique_ptr<uint8_t[]> buf(new uint8_t[size]());

    if(ReadProcessMemory64(hModule, buf.get(), size, 0) != STATUS_SUCCESS)
        return 0;

    IMAGE_NT_HEADERS64* inh   = (IMAGE_NT_HEADERS64*)(buf.get() + ((IMAGE_DOS_HEADER*)buf.get())->e_lfanew);
    IMAGE_DATA_DIRECTORY& idd = inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (idd.VirtualAddress == 0)
        return 0;

    IMAGE_EXPORT_DIRECTORY* ied = (IMAGE_EXPORT_DIRECTORY*)(buf.get() + idd.VirtualAddress);

    DWORD* rvaTable  = (DWORD*)(buf.get() + ied->AddressOfFunctions);
    WORD* ordTable   = (WORD*) (buf.get() + ied->AddressOfNameOrdinals);
    DWORD* nameTable = (DWORD*)(buf.get() + ied->AddressOfNames);

    // lazy search, there is no need to use binsearch for just one function
    for (DWORD i = 0; i < ied->NumberOfFunctions; i++)
    {
        WORD OrdIndex   = 0xFFFF;
        char *pName     = nullptr;

        // Find by index
        if((size_t)funcName <= 0xFFFF)
        {
            OrdIndex = (WORD)i;
        }
        // Find by name
        else if((size_t)funcName > 0xFFFF && i < ied->NumberOfNames)
        {
            pName    = (char*)(nameTable[i] + (size_t)buf.get());            
            OrdIndex = (WORD)ordTable[i];
        }
        else
            return 0;

        if(((size_t)funcName <= 0xFFFF && (WORD)funcName == (OrdIndex + ied->Base)) || ((size_t)funcName > 0xFFFF && strcmp(pName, funcName) == 0))
        {
            DWORD64 pFunc = (DWORD64)(rvaTable[OrdIndex] + hModule);

            // Check forwarded export
            if(pFunc >= hModule + idd.VirtualAddress && pFunc <= hModule + idd.VirtualAddress + idd.Size)
            {
                char forwardStr[255] = {0};
                DWORD size = 0;

                ReadProcessMemory64(pFunc, forwardStr, sizeof(forwardStr), 0);

                std::string  chainExp(forwardStr);
                std::wstring wchainExp(chainExp.begin(), chainExp.end());

                std::wstring strDll  = wchainExp.substr(0, wchainExp.find(L".")) + L".dll";
                std::string strName  = chainExp.substr(chainExp.find(".") + 1, strName.npos);

                DWORD64 hChainMod = GetModuleHandle64(strDll.c_str(), &size);

                // Import by ordinal
                if(strName.find("#") == 0)
                    return GetProcAddress64(hChainMod, size, (const char*)atoi(strName.c_str() + 1));
                // Import by name
                else
                    return GetProcAddress64(hChainMod, size, strName.c_str());
            }

            return pFunc;
        }
        /*if (strcmp((char*)buf.get() + nameTable[i], funcName))
            continue;
        else
        {
            return (DWORD64)(hModule + rvaTable[ordTable[i]]);
        }*/
    }

    return 0;
}

/*
*/
BOOL WoW64dm::CreateRemoteThread64( DWORD64 address, DWORD64 arg, bool wait /*= false*/ )
{
    DWORD64 hKernel32 = _local.GetModuleHandle64(L"kernelbase.dll");
    if(hKernel32 == 0)
        hKernel32 = _local.LoadLibrary64(L"C:\\windows\\system32\\kernelbase.dll");

    if(hKernel32 != 0)
    {
        DWORD64 pfnCreateThread = _local.GetProcAddress64(hKernel32, "CreateRemoteThread");

        if(pfnCreateThread != 0)
        {
            DWORD64 hThread = _local.X64Call(pfnCreateThread, 7, (DWORD64)_hProcess, (DWORD64)0, (DWORD64)0, address, arg, (DWORD64)0, (DWORD64)0);

            if(hThread != 0)
            {
                if(wait)
                    WaitForSingleObject((HANDLE)hThread, INFINITE);

                return TRUE;
            }
        }
    }

    return FALSE;
}

BOOL WoW64dm::LoadLibrary64( const wchar_t* path )
{
    BOOL isWOW = FALSE;
    IsWow64Process(_hProcess, &isWOW);

    // Inject into x64
    if(isWOW == FALSE)
    {
        DWORD64 memptr = 0;

        VirtualAllocEx64(memptr, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        if(memptr != 0)
        {
            DWORD size = 0;

            DWORD64 hKernel32 = GetModuleHandle64(L"Kernel32.dll", &size);
            DWORD64 pLoadLib  = GetProcAddress64(hKernel32, size, "LoadLibraryW");

            if(pLoadLib != 0 && WriteProcessMemory64(memptr, (LPVOID)path, (wcslen(path) + 1)*sizeof(wchar_t), 0) == STATUS_SUCCESS)
            {
                if(CreateRemoteThread64(pLoadLib, memptr, true) != FALSE)
                {
                    VirtualFreeEx64(memptr, 0x1000, MEM_RELEASE);
                    return TRUE;
                }
            }

            VirtualFreeEx64(memptr, 0x1000, MEM_FREE);
        }

        return FALSE;
    }
    // Inject into WOW64
    else
    {
        return LoadLibraryRemoteWOW64(path);
    }
}

/*
    Memory layout. 
    Function additionally writes Activation Context pointer into TEB for RtlQueryInformationActivationContext.

    ------------------------------------------------------------------------------------
    |  Return handle  |   UNICODE_STRING   |  dll path  |  padding  | executable code  | 
    ------------------------------------------------------------------------------------
*/
BOOL WoW64dm::LoadLibraryRemoteWOW64( const wchar_t* path )
{
    DWORD64 memptr = 0;
    int idx = 0;
    _UNICODE_STRING_T<DWORD64> upath = {0};

    VirtualAllocEx64(memptr, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if(memptr != 0)
    {
        DWORD size = 0;
        DWORD64 hNtdll = GetModuleHandle64(L"ntdll.dll", &size);
        DWORD64 pfnLdrLoadDll = GetProcAddress64(hNtdll, size, "LdrLoadDll");

        upath.Length        = wcslen(path) * sizeof(wchar_t);
        upath.MaximumLength = upath.Length;
        upath.Buffer        = memptr + 0x100;
        DWORD64 codeAddr    = memptr + 0xA00;

        uint8_t code[] = 
        { 
            // Enter x64 mode
            0x6A, 0x33, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x83, 0x04, 0x24, 0x05, 0xCB,         

            0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00,           // mov rax, gs:[30]
            0x48, 0xBA, 0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE,     // movabs rdx, 0xdeadbeefdeadbeef
            0x48, 0x89, 0x90, 0xC8, 0x02, 0x00, 0x00,                       // mov QWORD PTR [rax+0x2c8],rdx
            0x48, 0x89, 0xE5,                                               // mov rbp, rsp
            0x48, 0x83, 0xE4, 0xF0,                                         // and rsp, 0xfffffffffffffff0
            0x48, 0x83, 0xEC, 0x28,                                         // sub rsp, 0x30
            0x48, 0x31, 0xC9,                                               // xor rcx, rcx
            0x48, 0x31, 0xD2,                                               // xor rdx, rdx
            0x49, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE,     // movabs r8, &upath                        
            0x49, 0xB9, 0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE,     // movabs r9, &memptr
            0x48, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE,     // movabs rax, LdrLoadDll
            //0xCC, 
            0xFF, 0xD0,                                                     // call rax
            0x48, 0x89, 0xEC,                                               // mov rsp, rbp

            // Leave x64 mode
            0xE8, 0x00, 0x00, 0x00, 0x00, 0xC7, 0x44, 0x24, 0x04, 0x23, 0x00, 0x00, 0x00, 0x83, 0x04, 0x24, 0x0D, 0xCB, 
            0xC2, 0x04, 0x00    // retn 0x4
        };

        DWORD64 patch[] = { memptr + 0x700, memptr + 0x10, memptr, pfnLdrLoadDll };

        // Patch immediate memory values
        for(uint8_t* ptr = code; ptr < (code + sizeof(code) - 8); ptr++)
        {
            if(*(DWORD64*)ptr == (DWORD64)0xDEADBEEFDEADBEEF)
            {
                *(DWORD64*)ptr = patch[idx];
                idx++;
            }
        }

        if(WriteProcessMemory64(memptr + 0x10, &upath, sizeof(upath), 0) == STATUS_SUCCESS &&
           WriteProcessMemory64(upath.Buffer, (LPVOID)path, upath.Length + sizeof(wchar_t), 0) == STATUS_SUCCESS &&
           WriteProcessMemory64(codeAddr, code, sizeof(code), 0) == STATUS_SUCCESS)
        {
            if(CreateRemoteThread64(codeAddr, 0, true) != FALSE)
            {
                VirtualFreeEx64(memptr, 0x1000, MEM_RELEASE);
                return TRUE;
            }
        }

        VirtualFreeEx64(memptr, 0x1000, MEM_FREE);
    }        

    return FALSE;
}

}
