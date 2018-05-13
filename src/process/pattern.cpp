#include "include/process/pattern.h"
#include <cassert>
#include <iostream>

using namespace mem;
using namespace std;

uintptr_t mem::find_pattern(uintptr_t address, size_t module_length, const std::string& signature) {
	if(signature.length() > module_length) return 0;

	uintptr_t end = address + module_length - signature.length();
	uintptr_t off;
	while(address < end) {
		off = 0;
		for(const char c : signature) {
			if(((uint8_t*) address)[off++] == (uint8_t) c) continue;
			goto next;
		}
		return address;
		next:
		address++;
	}
	return 0;
}

uintptr_t mem::find_pattern(uintptr_t address, size_t module_length, const std::string &signature, const std::string &pattern) {
	if(signature.length() > module_length) return 0;
	assert(pattern.length() == signature.length());

	uintptr_t end = address + module_length - signature.length();
	uintptr_t off;
	while(address < end) {
		off = 0;
		for(const char c : signature) {
			if(pattern[off] == '?') { off++; continue; }
			if(((uint8_t*) address)[off++] == (uint8_t) c) continue;
			goto next;
		}
		return address;
		next:
		address++;
	}
	return 0;
}

uintptr_t mem::find_pattern(const shared_ptr<MemoryRegion>& region, const std::string& signature) {
	return mem::find_pattern(region->start, region->size(), signature);
}
uintptr_t mem::find_pattern(const shared_ptr<MemoryRegion>& region, const std::string& signature, const std::string& pattern) {
	return mem::find_pattern(region->start, region->size(), signature, pattern);
}

#ifndef WIN32
	#include "include/process/process.h"
	uintptr_t mem::find_pattern(const std::shared_ptr<process::ProcessInfo>& process, const std::string &signature, const std::string &pattern) {
		if(process->regions().empty())
			process->parseMemoryRegions();
		for(const auto& region : process->regions()) {
			auto result = find_pattern(region->start, region->size(), signature, pattern);
			if(result > 0) return result;
		}
		return 0;
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
#endif