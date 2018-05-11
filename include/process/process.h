#pragma once

#include <memory>
#include <deque>
#include <zconf.h>
#include "module.h"

namespace process {
	struct ProcessInfo {
		public:
			explicit ProcessInfo(pid_t);
			explicit ProcessInfo(const std::string&);

			std::string path();
			std::string workingDirectory();
			pid_t pid;

			inline bool valid() { return pid > 0; }
			bool running();


			void parseMemoryRegions();
			inline std::deque<std::shared_ptr<mem::MemoryRegion>> regions() { return this->_regions; }
			std::shared_ptr<mem::MemoryRegion> region(uintptr_t address);
			//uintptr_t pageAddress(uintptr_t);
		private:
			std::deque<std::shared_ptr<mem::MemoryRegion>> _regions;
	};

	std::shared_ptr<ProcessInfo> findByName(const std::string&);
	std::shared_ptr<ProcessInfo> findById(pid_t);

	inline pid_t ownId() { return getpid(); }
	std::shared_ptr<ProcessInfo> self();
}