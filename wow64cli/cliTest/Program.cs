using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;

namespace cliTest
{
    class Program
    {
        static void Main(string[] args)
        {
            wow64cli.MEMORY_BASIC_INFORMATION64m memBasic = null;
            wow64cli.wow64Process proc = new wow64cli.wow64Process();
            byte[] buf = new byte[0x1000];
            uint status = 0;
            wow64cli.PageProtection old = 0;
            int size = 0;
            UInt64 ntdll = 0;
            var baseptr = (UInt64)Process.GetCurrentProcess().MainModule.BaseAddress;

            proc.Attach(Process.GetCurrentProcess().Id);
            ntdll  = proc.GetModuleHandle64("ntdll.dll", ref size);
            status = proc.VirtualQueryEx64(baseptr, ref memBasic);
            status = proc.ReadProcessMemory64(ntdll, ref buf, 0x1000);
            status = proc.VirtualProtectEx64(baseptr, 0x1000, wow64cli.PageProtection.page_readwrite, ref old);
            var res = proc.LoadLibrary64("C:\\windows\\system32\\kernelbase.dll");

            System.Console.WriteLine(res);
            System.Console.ReadKey(true);
        }
    }
}
