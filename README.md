# GetModuleHandle - C# implementation

This function takes a DLL name, walks the PEB (Ldr) and returns the DLL base address. 

It works like the [GetModuleHandle](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea) function so it is useful if you want to avoid using it. This implementation uses only the NtQueryInformationProcess API call.

It is the same idea than Sektor7's Malware Intermediate course by [reenz0h](https://twitter.com/reenz0h), but in that course the code is C++ and I wanted a implementation like this in C#, I could not find it so maybe this is useful for someone else.

There is a binary to test the functionality: 

![img](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/getModuleHandle/Screenshot_1.png)
