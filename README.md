### BRAINSTORMING
---

I want to be able to inject my `Sliver C2` stager without being detected by Windows Defender, I already tried with Enumerating RWX Protected Memory Regions, so now I want to try this one. I've heard about directly using syscalls, but I wanted to try this one first, to understand a little bit better about how exported functions and API hashing works. If all works well, I would probably transform it into a dll and perform a dll sideloading.


### TODO
---

+ [ x ] Build a custom GetProcAddress
+ [ x ] Identify API Calls that I need (NtAllocateVirtualMemory, NtProtectVirtualMemory, NtWriteVirtualMemory, NtCreateThreadEx)
+ [ x ] Build a custom GetModuleHandle
+ [ x ] Implement API Hashing
+ [ x ] Perform an injection
+ [ ] Transform into a DLL Sideloading