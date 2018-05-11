#pragma once

#include <memory>
#include <string>
#include <cstddef>

namespace mem {
	uintptr_t find_pattern(uintptr_t address, size_t module_length, const std::string& signature);
	uintptr_t find_pattern(const std::shared_ptr<process::ProcessInfo>&, const std::string& signature);

	uintptr_t find_pattern(uintptr_t address, size_t module_length, const std::string& signature, const std::string& pattern);
	uintptr_t find_pattern(const std::shared_ptr<process::ProcessInfo>&, const std::string& signature, const std::string& pattern);
}