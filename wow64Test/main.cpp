#include "../wow64dm.h"
//#include <winioctl.h>
//#include "../../DarkMMap/VADPurge/VADPurgeDef.h"

int wmain(int argc, wchar_t* argv[])
{
    ds_wow64::WoW64dm wow64;
    NTSTATUS status = 0;
    DWORD size = 0;
    TEB64 teb = {0};
    PEB64 peb = {0};
    DWORD64 addr = 0x100000000;   

    wow64.Attach(GetCurrentProcess());
    DWORD64 pteb = (DWORD64)wow64.local().getTEB64(teb);

    HANDLE hThd = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, 0x1B90);

    // Fix 8TB memory block VAD
    /*HANDLE hFile = CreateFileW(L"\\\\.\\VadPurge", GENERIC_ALL, 0, NULL, OPEN_EXISTING, 0, NULL);
    if(hFile != INVALID_HANDLE_VALUE)
    {     
        PURGE_DATA data = { GetCurrentProcessId(), 1, { (ULONGLONG)0x80000000, 0x1000 } };
        DWORD junk      = 0;

        BOOL ret = DeviceIoControl(hFile, IOCTL_VADPURGE_ENABLECHANGE, &data, sizeof(data), NULL, 0, &junk, NULL);

        CloseHandle(hFile);
    }*/

    status = wow64.VirtualProtectEx64(addr, 0x1000, PAGE_READWRITE, &size);
    //status = wow64.VirtualFreeEx64(addr, 0x1000, MEM_RELEASE);
    //status = wow64.VirtualAllocEx64(addr, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    status = wow64.WriteProcessMemory64(addr, &teb, sizeof(teb), 0);

    //for(int i = 0; i < 1000000; i++)
        //status = wow64.WriteProcessMemory64(addr + 0x1000 * i, &teb, sizeof(teb), 0);

    DWORD64 result    = wow64.LoadLibrary64(L"C:\\windows\\system32\\Kernel32.dll");
    DWORD64 hKernel32 = wow64.GetModuleHandle64(L"Kernel32.dll", &size);
    DWORD64 encodeptr = wow64.GetProcAddress64(hKernel32, size, "EncodePointer");
    DWORD64 ppeb      = wow64.getPEB64(peb);
    pteb              = wow64.getTEB64(hThd, teb); 

    //wow64.LoadLibraryRemote64(L"C:\\Users\\Ton\\Documents\\Visual Studio 2012\\Projects\\NoCRT\\x64\\Release\\NoCRT.dll");
    //wow64.LoadLibrary64(L"C:\\Users\\Ton\\Documents\\Visual Studio 2012\\Projects\\NoCRT\\x64\\Release\\NoCRT.dll");
    //wow64.LoadLibraryRemote64(L"C:\\windows\\system32\\user32.dll");

	return 0;
}

