#include "include/process/module.h"

#ifdef WIN32
	#include <Windows.h>
	#include <Psapi.h>
#endif

using namespace std;
using namespace mem;

#ifdef WIN32
    std::shared_ptr<MemoryRegion> mem::info(const std::string& name) {
        auto result = make_shared<MemoryRegion>();

        MODULEINFO modinfo = { nullptr, 0, nullptr };
        const HMODULE module_handle = GetModuleHandle(name.c_str());
        if (!module_handle) return nullptr;
        GetModuleInformation(GetCurrentProcess(), module_handle, &modinfo, sizeof(MODULEINFO));

        result->start = reinterpret_cast<uintptr_t>(modinfo.lpBaseOfDll);
        result->end = reinterpret_cast<uintptr_t>(modinfo.lpBaseOfDll) + modinfo.SizeOfImage;

        return result;
    }
#endif