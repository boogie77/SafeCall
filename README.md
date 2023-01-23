## SafeCall
An x86 Windows, header only library for changing the _ReturnAddress location of a function.

## Implementation
- The implementation of SafeCall is meant to be simple and easy for anybody! All you have to do is take the code from SafeCall.h and paste it into your project.

## Compatibility
#### Known Device Compatibility:
- Windows (x86, x64)

#### Known Program Compatibility:
- DLL (Dynamic Link Library)
- EXE (Executable)

## Macros
SafeCall has 4 available macros; they look like this:
```cpp
SAFECALL_STDCALL, SAFECALL_THISCALL, SAFECALL_FASTCALL, SAFECALL_CDECL
```

## Usage
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
