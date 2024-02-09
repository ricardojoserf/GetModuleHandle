# GetModuleHandle - Custom implementation in C#

It works like the [GetModuleHandle](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea) WinAPI: it takes a DLL name, walks the PEB structure and returns the DLL base address. 

It only uses the [NtQueryInformationProcess](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess) native API call, without using structs.

It works in both 32-bit and 64-bit processes. You can test this using the binaries in the Releases section: 

![img](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/getModuleHandle/Screenshot_2.png)


-----------------------------------

### Sources

- Sektor7's Malware Intermediate course by [reenz0h](https://twitter.com/reenz0h) implements this code in C++

- tebpeb32.h: [https://bytepointer.com/resources/tebpeb32.htm](https://bytepointer.com/resources/tebpeb64.htm)

- tebpeb64.h: [https://bytepointer.com/resources/tebpeb64.htm](https://bytepointer.com/resources/tebpeb64.htm)
