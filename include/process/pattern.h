#pragma once

#include <memory>
#include <string>
#include <cstddef>
#include "module.h"

namespace mem {
	uintptr_t find_pattern(uintptr_t address, size_t length, const std::string& signature);
	uintptr_t find_pattern(uintptr_t address, size_t length, const std::string& signature, const std::string& pattern);

	uintptr_t find_pattern(const std::shared_ptr<MemoryRegion>&, const std::string& signature);
	uintptr_t find_pattern(const std::shared_ptr<MemoryRegion>&, const std::string& signature, const std::string& pattern);
	//The process stuff not yet implemented for windows

#if false
//#ifndef WIN32
	uintptr_t find_pattern(const std::shared_ptr<process::ProcessInfo>&, const std::string& signature);
	uintptr_t find_pattern(const std::shared_ptr<process::ProcessInfo>&, const std::string& signature, const std::string& pattern);
#endif
}