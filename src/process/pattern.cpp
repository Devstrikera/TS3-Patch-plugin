#include "include/process/process.h"
#include "include/process/pattern.h"

uintptr_t mem::find_pattern(uintptr_t address, size_t module_length, const std::string& pattern) {
	if(pattern.length() > module_length) return 0;

	uintptr_t end = address + module_length - pattern.length();
	uintptr_t off;
	while(address < end) {
		off = 0;
		for(const char c : pattern)
			if(((uint8_t*) address)[off++] != c) goto next;
		return address;
		next:
		address++;
	}
}

uintptr_t mem::find_pattern(const std::shared_ptr<process::ProcessInfo>& process, const std::string &pattern) {
	if(process->regions().empty())
		process->parseMemoryRegions();
	for(const auto& region : process->regions()) {
		auto result = find_pattern(region->start, region->size(), pattern);
		if(result > 0) return result;
	}
	return 0;
}

uintptr_t mem::find_pattern(uintptr_t address, size_t module_length, const std::string &signature, const std::string &pattern) {
	if(pattern.length() > module_length) return 0;

	uintptr_t end = address + module_length - pattern.length();
	uintptr_t off;
	while(address < end) {
		off = 0;
		for(const char c : pattern)
			if(pattern[off] != '?' && ((uint8_t*) address)[off++] != c) goto next;
		return address;
		next:
		address++;
	}
}

uintptr_t mem::find_pattern(const std::shared_ptr<process::ProcessInfo>& process, const std::string &signature, const std::string &pattern) {
	if(process->regions().empty())
		process->parseMemoryRegions();
	for(const auto& region : process->regions()) {
		auto result = find_pattern(region->start, region->size(), signature, pattern);
		if(result > 0) return result;
	}
	return 0;
}