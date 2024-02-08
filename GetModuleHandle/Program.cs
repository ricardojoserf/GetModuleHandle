using System;
using System.Diagnostics;
using System.Runtime.InteropServices;


namespace GetModuleHandle
{
    internal class Program
    {
        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtQueryInformationProcess(
            IntPtr processHandle,
            int processInformationClass,
            IntPtr pbi,
            uint processInformationLength,
            out IntPtr returnLength
        );

        public unsafe static IntPtr CustomGetModuleHandle(String dll_name, uint process_basic_information_size, int peb_offset, int ldr_offset, int inInitializationOrderModuleList_offset, int flink_dllbase_offset, int flink_buffer_offset)
        {
            IntPtr hProcess = Process.GetCurrentProcess().Handle;

            // Create byte array with the size of the PROCESS_BASIC_INFORMATION structure
            byte[] pbi_byte_array = new byte[process_basic_information_size];

            // Create a PROCESS_BASIC_INFORMATION structure in the byte array
            IntPtr pbi_addr = IntPtr.Zero;
            fixed (byte* p = pbi_byte_array)
            {
                pbi_addr = (IntPtr)p;             
                NtQueryInformationProcess(hProcess, 0x0, pbi_addr, process_basic_information_size, out _);
                Console.WriteLine("[+] Process_Basic_Information Address: \t\t0x" + pbi_addr.ToString("X"));
            }

            // Get PEB Base Address
            IntPtr peb_pointer = pbi_addr + peb_offset;
            Console.WriteLine("[+] PEB Address Pointer:\t\t\t0x"+peb_pointer.ToString("X"));
            IntPtr pebaddress = Marshal.ReadIntPtr(peb_pointer);
            Console.WriteLine("[+] PEB Address:\t\t\t\t0x" + pebaddress.ToString("X"));

            // Get Ldr 
            IntPtr ldr_pointer = pebaddress + ldr_offset;
            IntPtr ldr_adress = Marshal.ReadIntPtr(ldr_pointer);
            Console.WriteLine("[+] LDR Pointer:\t\t\t\t0x" + ldr_pointer.ToString("X"));
            Console.WriteLine("[+] LDR Address:\t\t\t\t0x" + ldr_adress.ToString("X"));

            // Get InInitializationOrderModuleList (LIST_ENTRY) inside _PEB_LDR_DATA struct
            IntPtr InInitializationOrderModuleList = ldr_adress + inInitializationOrderModuleList_offset;             
            Console.WriteLine("[+] InInitializationOrderModuleList:\t\t0x" + InInitializationOrderModuleList.ToString("X"));

            IntPtr next_flink = Marshal.ReadIntPtr(InInitializationOrderModuleList);
            IntPtr dll_base = (IntPtr)1337;
            while (dll_base != IntPtr.Zero)
            {
                next_flink = next_flink - 0x10;
                // Get DLL base address
                dll_base = Marshal.ReadIntPtr(next_flink + flink_dllbase_offset);
                IntPtr buffer = Marshal.ReadIntPtr(next_flink + flink_buffer_offset);
                // Get DLL name from buffer address
                String char_aux = null;
                String base_dll_name = "";
                while (char_aux != "")
                {
                    char_aux = Marshal.PtrToStringAnsi(buffer);
                    buffer += 2;
                    base_dll_name += char_aux;
                }
                next_flink = Marshal.ReadIntPtr(next_flink + 0x10);
                // Compare with DLL name we are searching
                if (dll_name.ToLower() == base_dll_name.ToLower())
                {
                    return dll_base;
                }
            }

            return IntPtr.Zero;
        }

        static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("[-] Usage: GetModuleHandle.exe DLL_NAME.dll");
                System.Environment.Exit(0);
            }
            string dll_name = args[0];
            IntPtr base_address = IntPtr.Zero;
            if (IntPtr.Size == 4)
            {
                Console.WriteLine("[+] 32-bit process");
                base_address = CustomGetModuleHandle(dll_name, 24, 0x4, 0x0c, 0x1c, 0x18, 0x30);
            }
            else if (IntPtr.Size == 8)
            {
                Console.WriteLine("[+] 64-bit process");
                base_address = CustomGetModuleHandle(dll_name, 48, 0x8, 0x18, 0x30, 0x20, 0x50);
            }
            
            if (base_address == IntPtr.Zero)
            {
                Console.WriteLine("[-] DLL name not found");
            }
            else
            {
                Console.WriteLine("[+] RESULT: \t\t\t\t\t0x{1}", dll_name, base_address.ToString("X"));
                // Console.WriteLine("[+] Base address of {0}: \t0x{1} [GetModuleHandle]", dll_name, GetModuleHandle(dll_name).ToString("X"));
            }
        }
    }
}