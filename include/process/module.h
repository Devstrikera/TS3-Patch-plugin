#pragma once

#include <string>

namespace mem {
	struct MemoryRegion {
		uintptr_t start;
		uintptr_t end;

		// Permissions
		bool readable;
		bool writable;
		bool executable;
		bool shared;

		// File data
		uintptr_t offset;
		unsigned char deviceMajor;
		unsigned char deviceMinor;
		unsigned long inodeFileNumber;
		std::string pathname;
		std::string filename;

		unsigned long client_start;

		inline size_t size() { return end - start; }
	};
}