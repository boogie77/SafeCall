## SafeCall
An x86 Windows, header only library for changing the _ReturnAddress location of a function. The primary goal of SafeCall is have the _ReturnAddress change in an extremely stealthy matter. The library by default includes various useful functions apart from the primary implementation to be more secure. i.e: ```GetExport``` and ```GetModule```. I believe it's very important to not call nor use any WindowsAPI functions to be even more discreet.

Note to more advanced users: If you'd like to be even more secretive, you can hash the strings that SafeCall imports. I've decided not to do this to keep the implementation minimal.

## Implementation
- The implementation of SafeCall is meant to be simple and easy for anybody! All you have to do is take the code from SafeCall.h and paste it into your project.

## Compatibility
#### Known Device Compatibility:
- Windows (x86, x64)

#### Known Program Compatibility:
- DLL (Dynamic Link Library)
- EXE (Executable)

## Macro Explanation
SafeCall has 4 available macros; they look like this:
```cpp
SAFECALL_STDCALL, SAFECALL_THISCALL, SAFECALL_FASTCALL, SAFECALL_CDECL
```

- STDCALL is for [__stdcall](https://learn.microsoft.com/en-us/cpp/cpp/stdcall?view=msvc-170) functions. You want to use this on WinAPI functions such as, MessageBoxA, VirtualProtect, ExitProcess, etc.
- THISCALL is for [__thiscall](https://learn.microsoft.com/en-us/cpp/cpp/thiscall?view=msvc-170) functions. __thiscall Functions are by default, class member functions in x86. It's the default convention used by member functions that don't use variable arguments.
- FASTCALL is for [__fastcall](https://learn.microsoft.com/en-us/cpp/cpp/fastcall?view=msvc-170) functions. This is a calling convention that specifices that arguments to functions are to be passed in registers when possible. Of course, It attempts have execution quicker.
- CDECL is for [__cdecl](https://learn.microsoft.com/en-us/cpp/cpp/cdecl?view=msvc-170) functions. This convention type is Microsoft specific. It's the default convention for C & C++ programs. It can do vararg functions.

## Testing
![This is an image](https://i.imgur.com/PaDvDqv.png)

## Real Usage
Example usage of SafeCall:

```cpp
#include <Windows.h>

#include "SafeCall.h"

#define LOG(...) printf(__VA_ARGS__); \

class VirtualStuff
{
public:
    virtual int GetEntityCount()
    {
        return 128;
    }
};

inline uintptr_t GetVirtual(void* classBase, size_t index)
{
    return static_cast<uintptr_t>((*static_cast<int**>(classBase))[index]);
}

int main()
{
    while (!GetModuleHandleA("user32.dll"))
        LoadLibraryA("user32.dll");

    LOG("[+] Found user32.dll\n");

    VirtualStuff* exampleClass = new VirtualStuff();
    void* virtualFunctionAddress = (void*)GetVirtual(exampleClass, 0);
    LOG("[+] GetEntityCount address: 0x%p\n", virtualFunctionAddress);

    auto GetEntityCountSpoofed = [](void* vfuncAddy) -> int
    {
        return SafeCall::Type::Stdcall<int>(uintptr_t(vfuncAddy), SafeCall::Address::GetGadget("user32.dll"));
    };

    LOG("[+] Player count: %i\n", GetEntityCountSpoofed(virtualFunctionAddress));

    SafeCall::Type::Stdcall<int>(SafeCall::Address::GetExport("user32.dll", "MessageBoxA"), SafeCall::Address::GetGadget("user32.dll"), nullptr, "Spoofed call", "Alert", MB_OK);

    std::cin.get();
    return EXIT_SUCCESS;
}
```
