#include "Wow64Local.h"


namespace ds_wow64
{

Wow64Local::Wow64Local(void)
    : _ntdll64(0)
    , _ntdll64Size(0)
    , _LdrGetProcedureAddress(0)
    , ntqvm(0)
    , ntavm(0)
    , ntfvm(0)
    , ntrvm(0)
    , ntwvm(0)
    , ntpvm(0)
    , gtc(0)
    , stc(0)
{
    HMODULE ntdll32 = GetModuleHandleW(L"Ntdll.dll");

    _NtWow64QIP = (fnNtWow64QIP)GetProcAddress (ntdll32, "NtWow64QueryInformationProcess64");
    _NtRPM      = (fnNtWow64VmOp)GetProcAddress(ntdll32, "NtWow64ReadVirtualMemory64");
    _NtWPM      = (fnNtWow64VmOp)GetProcAddress(ntdll32, "NtWow64WriteVirtualMemory64");
}


Wow64Local::~Wow64Local(void)
{
}


/*
*/
DWORD64 Wow64Local::X64Call( DWORD64 func, int argC, ... )
{
    va_list args;
	va_start(args, argC);

	return X64CallV(func, argC, args);
}


/*
*/
// warning C4409: illegal instruction size
#pragma warning(disable : 4409)
DWORD64 Wow64Local::X64CallV( DWORD64 func, int argC, va_list args )
{
    DWORD64 _rcx = (argC > 0) ? argC--, va_arg(args, DWORD64) : 0;
	DWORD64 _rdx = (argC > 0) ? argC--, va_arg(args, DWORD64) : 0;
	DWORD64 _r8 = (argC > 0) ? argC--, va_arg(args, DWORD64) : 0;
	DWORD64 _r9 = (argC > 0) ? argC--, va_arg(args, DWORD64) : 0;
	reg64 _rax;
	_rax.v = 0;

	DWORD64 restArgs = (DWORD64)&va_arg(args, DWORD64);
	
	//conversion to QWORD for easier use in inline assembly
	DWORD64 _argC = argC;
	DWORD64 _func = func;

	DWORD back_esp = 0;

	__asm
	{
		;//keep original esp in back_esp variable
		mov    back_esp, esp
		
		;//align esp to 8, without aligned stack some syscalls may return errors !
		and    esp, 0xFFFFFFF8

		X64_Start();

		;//fill first four arguments
		push   _rcx
		X64_Pop(_RCX);
		push   _rdx
		X64_Pop(_RDX);
		push   _r8
		X64_Pop(_R8);
		push   _r9
		X64_Pop(_R9);
	
		push   edi

		push   restArgs
		X64_Pop(_RDI);

		push   _argC
		X64_Pop(_RAX);

		;//put rest of arguments on the stack
		test   eax, eax
		jz     _ls_e
		lea    edi, dword ptr [edi + 8*eax - 8]

		_ls:
		test   eax, eax
		jz     _ls_e
		push   dword ptr [edi]
		sub    edi, 8
		sub    eax, 1
		jmp    _ls
		_ls_e:

		;//create stack space for spilling registers
		sub    esp, 0x20

		call   _func

		;//cleanup stack
		push   _argC
		X64_Pop(_RCX);
		lea    esp, dword ptr [esp + 8*ecx + 0x20]

		pop    edi

		//set return value
		X64_Push(_RAX);
		pop    _rax.dw[0]

		X64_End();

		mov    esp, back_esp
	}

	return _rax.v;
}
#pragma warning(default : 4409)

/*
*/
void __declspec(naked, noinline) Wow64Local::memcpy64(DWORD64 /*dst*/, DWORD64 /*src*/, DWORD /*size*/)
{
    /*
        mov rdi, QWORD PTR [rbp + 0x8]
        mov rsi, QWORD PTR [rbp + 0x10]
        mov ecx, DWORD PTR [rbp + 0x18]

      loop1:
        mov al, BYTE PTR [ri]
        mov BYTE PTR [rdi], al
        add rsi, 0x1
        add rdi, 0x1
        sub ecx, 0x1
        test ecx, ecx
      jnz loop1
    */
    
    __asm
    {
        push ebp
        mov ebp, esp
        pushad
    }

    X64_Start();

    EMIT(0x48) EMIT(0x8B) EMIT(0x7D) EMIT(0x08)
    EMIT(0x48) EMIT(0x8B) EMIT(0x75) EMIT(0x10)
    EMIT(0x8B) EMIT(0x4D) EMIT(0x18)
    EMIT(0x8A) EMIT(0x06)
    EMIT(0x88) EMIT(0x07)
    EMIT(0x48) EMIT(0x83) EMIT(0xC6) EMIT(0x01)                      
    EMIT(0x48) EMIT(0x83) EMIT(0xC7) EMIT(0x01)
    EMIT(0x83) EMIT(0xE9) EMIT(0x01)
    EMIT(0x85) EMIT(0xC9)
    EMIT(0x75) EMIT(0xED)

    X64_End();

    __asm
    {
        popad
        mov esp, ebp
        pop ebp
        retn 20
    }
}

/*
*/
DWORD64 Wow64Local::getTEB64( TEB64& out )
{
    reg64 reg;
    reg.v = 0;

    X64_Start();
    //R12 register should always contain pointer to TEB64 in WoW64 processes
    X64_Push(_R12);
    //below pop will pop QWORD from stack, as we're in x64 mode now
    __asm pop reg.dw[0]
    X64_End();

    memcpy64((DWORD64)&out, reg.v, sizeof(out));

    return reg.dw[0];
}

/*
*/
DWORD64 Wow64Local::GetModuleHandle64( wchar_t* lpModuleName, DWORD* pSize /*= nullptr*/ )
{
    DWORD64 module     = 0;
    TEB64 teb64        = {0};
    PEB64 peb64        = {0};
    PEB_LDR_DATA64 ldr = {0};

    getTEB64(teb64);

    memcpy64((DWORD64)&peb64, teb64.ProcessEnvironmentBlock, sizeof(peb64));
    memcpy64((DWORD64)&ldr, peb64.Ldr, sizeof(ldr));

    // Traverse 64bit modules
    for(DWORD64 head = ldr.InLoadOrderModuleList.Flink;
        head != (peb64.Ldr + FIELD_OFFSET(PEB_LDR_DATA64, InLoadOrderModuleList));
        memcpy64((DWORD64)&head, (DWORD64)head, sizeof(head)))
    {
        wchar_t localbuf[512]            = {0};
        LDR_DATA_TABLE_ENTRY64 localdata = {0};

        memcpy64((DWORD64)&localdata, head, sizeof(localdata));
        memcpy64((DWORD64)localbuf, localdata.BaseDllName.Buffer, localdata.BaseDllName.Length);

        if (_wcsicmp(localbuf, lpModuleName) == 0)
        {
            module = localdata.DllBase;
            if(pSize)
                *pSize = localdata.SizeOfImage;

            break;
        }
    }

    return module;
}

/*
*/
DWORD64 Wow64Local::getNTDLL64(DWORD* pSize /*= nullptr*/)
{
    if(_ntdll64 != 0)
    {
        if(pSize)
            *pSize = _ntdll64Size;

        return _ntdll64;
    }

    _ntdll64 = GetModuleHandle64(L"ntdll.dll", &_ntdll64Size);
    if(pSize)
        *pSize = _ntdll64Size;

    return _ntdll64;
}

/*
*/
DWORD64 Wow64Local::getLdrGetProcedureAddress()
{
    DWORD ntSize    = 0;
    DWORD64 modBase = getNTDLL64(&ntSize);

    if(modBase == 0 || ntSize == 0)
        return 0;

    std::unique_ptr<uint8_t[]> buf(new uint8_t[ntSize]());

    memcpy64((DWORD64)buf.get(), modBase, ntSize);

    IMAGE_NT_HEADERS64* inh   = (IMAGE_NT_HEADERS64*)(buf.get() + ((IMAGE_DOS_HEADER*)buf.get())->e_lfanew);
    IMAGE_DATA_DIRECTORY& idd = inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (0 == idd.VirtualAddress)
        return 0;

    IMAGE_EXPORT_DIRECTORY* ied = (IMAGE_EXPORT_DIRECTORY*)(buf.get() + idd.VirtualAddress);

    DWORD* rvaTable  = (DWORD*)(buf.get() + ied->AddressOfFunctions);
    WORD* ordTable   = (WORD*) (buf.get() + ied->AddressOfNameOrdinals);
    DWORD* nameTable = (DWORD*)(buf.get() + ied->AddressOfNames);

    //lazy search, there is no need to use binsearch for just one function
    for (DWORD i = 0; i < ied->NumberOfFunctions; i++)
    {
        if (strcmp((char*)buf.get() + nameTable[i], "LdrGetProcedureAddress"))
            continue;
        else
        {
            return (DWORD64)(modBase + rvaTable[ordTable[i]]);
        }
    }

    return 0;
}

/*
*/
DWORD64 Wow64Local::GetProcAddress64( DWORD64 hModule, char* funcName )
{
    if (0 == _LdrGetProcedureAddress)
    {
        _LdrGetProcedureAddress = getLdrGetProcedureAddress();
        if (0 == _LdrGetProcedureAddress)
            return 0;
    }

    _UNICODE_STRING_T<DWORD64> fName = { 0 };
    fName.Buffer = (DWORD64)funcName;
    fName.Length = (WORD)strlen(funcName);
    fName.MaximumLength = fName.Length + 1;

    DWORD64 funcRet = 0;
    X64Call(_LdrGetProcedureAddress, 4, (DWORD64)hModule, (DWORD64)&fName, (DWORD64)0, (DWORD64)&funcRet);

    return funcRet;
}

/*
*/
DWORD64 Wow64Local::LoadLibrary64( const wchar_t* path )
{
    _UNICODE_STRING_T<DWORD64> upath = {0};

    DWORD64 hModule     = 0;
    DWORD64 pfnLdrLoad  = (DWORD64)GetProcAddress64(getNTDLL64(), "LdrLoadDll");
    upath.Length        = (WORD)wcslen(path) * sizeof(wchar_t);
    upath.MaximumLength = (WORD)upath.Length;
    upath.Buffer        = (DWORD64)path;

    X64Call(pfnLdrLoad, 4, (DWORD64)NULL, (DWORD64)0, (DWORD64)&upath, (DWORD64)&hModule);

    return hModule;
};

}