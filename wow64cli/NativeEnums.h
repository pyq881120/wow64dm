#pragma once
#include <winnt.h>

#pragma managed

namespace wow64cli
{
    public enum class AllocType
    {
        mem_commit   = MEM_COMMIT,
        mem_reserve  = MEM_RESERVE,
        mem_decommit = MEM_DECOMMIT,
        mem_release  = MEM_RELEASE,
    };

    public enum class PageProtection
    {
        page_noaccess          = PAGE_NOACCESS,
        page_readonly          = PAGE_READONLY,
        page_readwrite         = PAGE_READWRITE,
        page_writecopy         = PAGE_WRITECOPY,
        page_execute           = PAGE_EXECUTE,
        page_execute_read      = PAGE_EXECUTE_READ,
        page_execute_readwrite = PAGE_EXECUTE_READWRITE,
        page_execute_writecopy = PAGE_EXECUTE_WRITECOPY,    
        page_guard             = PAGE_GUARD,
    };
};

#pragma unmanaged