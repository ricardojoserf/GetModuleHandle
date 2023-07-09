using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;


namespace GetModuleHandle
{
    internal class Program
    {
        // [DllImport("kernel32.dll", SetLastError = true)] static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);
        [DllImport("ntdll.dll", SetLastError = true)] static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, ref PROCESS_BASIC_INFORMATION pbi, uint processInformationLength, ref uint returnLength);
        // [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] public static extern IntPtr GetModuleHandle([MarshalAs(UnmanagedType.LPWStr)] string lpModuleName);
        private struct PROCESS_BASIC_INFORMATION { public uint ExitStatus; public IntPtr PebBaseAddress; public UIntPtr AffinityMask; public int BasePriority; public UIntPtr UniqueProcessId; public UIntPtr InheritedFromUniqueProcessId; }        
        // unsafe struct LIST_ENTRY { public byte* Flink; public byte* Blink; }
        // unsafe struct UNICODE_STRING { public ushort Length; public ushort MaximumLength; public char* Buffer; }
        // struct LDR_DATA_TABLE_ENTRY { public LIST_ENTRY InMemoryOrderLinks; public LIST_ENTRY InInitializationOrderList; public IntPtr DllBase; public IntPtr EntryPoint; private IntPtr Reserved3; public UNICODE_STRING FullDllName; public UNICODE_STRING BaseDllName; }
        

        private static T MarshalBytesTo<T>(byte[] bytes) { 
            GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned); 
            T theStructure = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T)); 
            handle.Free();
            return theStructure; 
        }


        unsafe static IntPtr auxGetModuleHandle(String dll_name) {
            IntPtr hProcess = Process.GetCurrentProcess().Handle;
            PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
            uint temp = 0;
            NtQueryInformationProcess(hProcess, 0x0, ref pbi, (uint)(IntPtr.Size * 6), ref temp);

            IntPtr ldr_pointer = (IntPtr)((Int64)pbi.PebBaseAddress + 0x18);
            IntPtr ldr_adress = Marshal.ReadIntPtr(ldr_pointer);

            // Source: https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntpsapi_x/peb_ldr_data.htm
            IntPtr InInitializationOrderModuleList = ldr_adress + 0x30;
            /*
            byte[] data5 = new byte[Marshal.SizeOf(typeof(LIST_ENTRY))];
            ReadProcessMemory(hProcess, InInitializationOrderModuleList, data5, data5.Length, out _);
            LIST_ENTRY inInitializationOrderModuleList_list_entry = MarshalBytesTo<LIST_ENTRY>(data5);
            IntPtr next_flink = ((IntPtr)inInitializationOrderModuleList_list_entry.Flink);
            */
            IntPtr next_flink = Marshal.ReadIntPtr(InInitializationOrderModuleList);
            Console.WriteLine(next_flink);
            
            IntPtr dll_base = (IntPtr) 1;

            /*
            // FOR DEBUGGING
            IntPtr InLoadOrderModuleList = ldr_adress + 0x10;
            IntPtr InMemoryOrderModuleList = ldr_adress + 0x20;

            // InLoadOrderModuleList
            byte[] data3 = new byte[Marshal.SizeOf(typeof(LIST_ENTRY))];
            ReadProcessMemory(hProcess, InLoadOrderModuleList, data3, data3.Length, out _);
            LIST_ENTRY InLoadOrderModuleList_list_entry = MarshalBytesTo<LIST_ENTRY>(data3);
            // InMemoryOrderModuleList
            byte[] data4 = new byte[Marshal.SizeOf(typeof(LIST_ENTRY))];
            ReadProcessMemory(hProcess, InMemoryOrderModuleList, data4, data4.Length, out _);
            LIST_ENTRY InMemoryOrderModuleList_list_entry = MarshalBytesTo<LIST_ENTRY>(data4);

            Console.WriteLine("LdrTest: \t\t\t\t\t\t0x" + ldr_adress.ToString("X"));
            Console.WriteLine("InLoadOrderModuleList: \t\t\t\t\t0x" + InLoadOrderModuleList.ToString("X"));
            Console.WriteLine("InLoadOrderModuleList_list_entry.Flink :\t\t0x" + ((int)InLoadOrderModuleList_list_entry.Flink).ToString("X"));
            Console.WriteLine("InLoadOrderModuleList_list_entry.Blink :\t\t0x" + ((int)InLoadOrderModuleList_list_entry.Blink).ToString("X"));
            Console.WriteLine("InMemoryOrderModuleList: \t\t\t\t0x" + InMemoryOrderModuleList.ToString("X"));
            Console.WriteLine("InMemoryOrderModuleList_list_entry.Flink :\t\t0x" + ((int)InMemoryOrderModuleList_list_entry.Flink).ToString("X"));
            Console.WriteLine("InMemoryOrderModuleList_list_entry.Blink :\t\t0x" + ((int)InMemoryOrderModuleList_list_entry.Blink).ToString("X"));
            Console.WriteLine("InInitializationOrderModuleList: \t\t\t0x" + InInitializationOrderModuleList.ToString("X"));
            Console.WriteLine("InInitializationOrderModuleList_list_entry.Flink :\t0x" + inInitializationOrderModuleList_list_entry_flink.ToString("X"));
            Console.WriteLine("InInitializationOrderModuleList_list_entry.Blink :\t0x" + ((int)inInitializationOrderModuleList_list_entry.Blink).ToString("X"));
            */

            while (dll_base != IntPtr.Zero)
            {
                next_flink = next_flink - 0x10;
                
                /*
                byte[] data6 = new byte[Marshal.SizeOf(typeof(LDR_DATA_TABLE_ENTRY))];
                ReadProcessMemory(hProcess, next_flink, data6, data6.Length, out _);
                LDR_DATA_TABLE_ENTRY ldr_data_table_entry_test = MarshalBytesTo<LDR_DATA_TABLE_ENTRY>(data6);
                */
                /*
                struct LDR_DATA_TABLE_ENTRY { public LIST_ENTRY InMemoryOrderLinks; public LIST_ENTRY InInitializationOrderList; public IntPtr DllBase; public IntPtr EntryPoint; private IntPtr Reserved3; public UNICODE_STRING FullDllName; public UNICODE_STRING BaseDllName; }
                */
                
                dll_base = Marshal.ReadIntPtr(next_flink + 0x20); // dll_base = ldr_data_table_entry_test.DllBase;
                
                // String base_dll_name = new String(ldr_data_table_entry_test.BaseDllName.Buffer);
                
                /*
                Int16 test = Marshal.ReadInt16(next_flink + 0x48);
                Console.WriteLine("Length: " + test);
                Int16 test2 = Marshal.ReadInt16(next_flink + 0x4a);
                Console.WriteLine("MaximumLength: " + test2);
                */
                IntPtr buffer = Marshal.ReadIntPtr(next_flink + 0x50);
                
                // Console.WriteLine("next_flink + 0x50: \t0x" + (next_flink + 0x50).ToString("X"));
                // Console.WriteLine("buffer:            \t0x" + buffer.ToString("X"));

                String char_aux = null;
                String base_dll_name = "";
                while (char_aux != "") {
                    char_aux = Marshal.PtrToStringAnsi(buffer);
                    buffer += 2;
                    base_dll_name += char_aux;
                }
                
                /*
                Console.WriteLine("ldr_data_table_entry_test.BaseDllName.Length: " + (int)ldr_data_table_entry_test.BaseDllName.Length);
                Console.WriteLine("ldr_data_table_entry_test.BaseDllName.MaximumLength: " + (int)ldr_data_table_entry_test.BaseDllName.MaximumLength);
                Console.WriteLine("ldr_data_table_entry_test.BaseDllName.Buffer: 0x" + ((int)ldr_data_table_entry_test.BaseDllName.Buffer).ToString("X"));
                */
                next_flink = Marshal.ReadIntPtr(next_flink + 0x10); // next_flink = (IntPtr)ldr_data_table_entry_test.InInitializationOrderList.Flink;

                // Console.WriteLine(base_dll_name);
                // Console.WriteLine(dll_base.ToString("X"));
                // Console.ReadLine();
                if (dll_name.ToLower() == base_dll_name.ToLower())
                {
                        return dll_base;
                }
                /*
                // FOR DEBUGGING
                Console.WriteLine("FullDllName:   \t" + new String(ldr_data_table_entry_test.FullDllName.Buffer));
                Console.WriteLine("BaseDllName:   \t" + base_dll_name);
                Console.WriteLine("DllBase:       \t0x" + dll_base.ToString("X"));
                Console.WriteLine("Flink:         \t0x{0}", next_flink.ToString("X"));
                Console.ReadLine();
                */
            }
            return IntPtr.Zero;
        }


        static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("[-] Usage: GetModuleHandle.exe DLL_NAME");
                System.Environment.Exit(0);
            }
            string dll_name = args[0];
            IntPtr base_address = auxGetModuleHandle(dll_name);

            if (base_address == IntPtr.Zero)
            {
                Console.WriteLine("[-] DLL name not found");
            }
            else
            {
                Console.WriteLine("[+] Base address of {0}: \t0x{1}", dll_name, base_address.ToString("X"));
                // Console.WriteLine("[+] Base address of {0}: \t0x{1} [GetModuleHandle]", dll_name, GetModuleHandle(dll_name).ToString("X"));
            }
        }
    }
}