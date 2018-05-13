#pragma once

#include <string>
#include <memory>

#ifdef WIN32
	#include <Windows.h>
#endif

namespace mem {
	struct MemoryRegion {
		uintptr_t start;
		uintptr_t end;

		// Permissions
#ifndef WIN32
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
#endif

		inline size_t size() { return end - start; }
	};

	std::shared_ptr<MemoryRegion> info(const std::string& name);
}