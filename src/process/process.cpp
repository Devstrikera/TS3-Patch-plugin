#include <dirent.h>
#include <zconf.h>
#include <iostream>
#include <include/process/file.h>
#include <fstream>
#include <sstream>
#include "../../include/process/process.h"

#ifdef NATIVE_FILESYSTEM
	#include <experimental/filesystem>
	namespace fs = std::experimental::filesystem;
	#define fs_path fs::u8path
#else
	#include <boost/filesystem.hpp>
	#include <boost/range/iterator_range.hpp>

	namespace fs = boost::filesystem;
	#define fs_path fs::path
#endif

using namespace std;
using namespace process;

ProcessInfo::ProcessInfo(pid_t pid) : pid(pid) {}
ProcessInfo::ProcessInfo(const std::string& path) {
	if(path.find_first_not_of("0123456789") == string::npos)
		this->pid = stoi(path);
	else
		this->pid = -1;
}

bool ProcessInfo::running() {
	if (!this->valid())
		return false;
	return fs::exists(fs_path("/proc/" + to_string(this->pid)));
}

std::string ProcessInfo::path() {
	return file::resolveSymbolicLink("/proc/" + to_string(this->pid) + "/exe");
}

std::string ProcessInfo::workingDirectory() {
	return file::resolveSymbolicLink("/proc/" + to_string(this->pid) + "/cwd");
}

void ProcessInfo::parseMemoryRegions() {
	this->_regions.clear();

	std::ifstream maps("/proc/" + to_string(this->pid) + "/maps");

	std::string line;
	while (std::getline(maps, line)) {
		std::istringstream iss(line);
		std::string memorySpace, permissions, offset, device, inode;
		if (iss >> memorySpace >> permissions >> offset >> device >> inode) {
			std::string pathname;

			for (size_t ls = 0, i = 0; i < line.length(); i++) {
				if (line.substr(i, 1).compare(" ") == 0) {
					ls++;

					if (ls == 5) {
						size_t begin = line.substr(i, line.size()).find_first_not_of(' ');

						if (begin != -1) {
							pathname = line.substr(begin + i, line.size());
						} else {
							pathname.clear();
						}
					}
				}
			}

			auto region = make_shared<mem::MemoryRegion>();

			size_t memorySplit = memorySpace.find_first_of('-');
			size_t deviceSplit = device.find_first_of(':');

			std::stringstream ss;

			if (memorySplit != -1) {
				ss << std::hex << memorySpace.substr(0, memorySplit);
				ss >> region->start;
				ss.clear();
				ss << std::hex << memorySpace.substr(memorySplit + 1, memorySpace.size());
				ss >> region->end;
				ss.clear();
			}

			if (deviceSplit != -1) {
				ss << std::hex << device.substr(0, deviceSplit);
				ss >> region->deviceMajor;
				ss.clear();
				ss << std::hex << device.substr(deviceSplit + 1, device.size());
				ss >> region->deviceMinor;
				ss.clear();
			}

			ss << std::hex << offset;
			ss >> region->offset;
			ss.clear();
			ss << inode;
			ss >> region->inodeFileNumber;

			region->readable = (permissions[0] == 'r');
			region->writable = (permissions[1] == 'w');
			region->executable = (permissions[2] == 'x');
			region->shared = (permissions[3] != '-');

			if (!pathname.empty()) {
				region->pathname = pathname;

				size_t fileNameSplit = pathname.find_last_of('/');

				if (fileNameSplit != -1) {
					region->filename = pathname.substr(fileNameSplit + 1, pathname.size());
				}
			}

			_regions.push_back(region);
		}
	}
}

std::shared_ptr<mem::MemoryRegion> ProcessInfo::region(uintptr_t address) {
	for(const auto& e : this->_regions)
		if(e->start <= address && e->end >= address) return e;
	return nullptr;
}

/*
uintptr_t ProcessInfo::pageAddress(uintptr_t address) {
	auto module = this->region(address);
	if(!module) return 0;

}
 */

std::shared_ptr<ProcessInfo> process::self() {
	return make_shared<ProcessInfo>(ownId());
}

std::shared_ptr<ProcessInfo> process::findById(pid_t pid) {
	return make_shared<ProcessInfo>(pid);
}

shared_ptr<ProcessInfo> process::findByName(const std::string& name) {
#ifdef NATIVE_FILESYSTEM
	for(const auto& entry : fs::directory_iterator(fs_path("/proc/"))) {
#else
	for(const auto& entry : boost::make_iterator_range(fs::directory_iterator(fs_path("/proc/")), {})) {
#endif
		auto path_map = entry.path();
		path_map /= "maps";
		if (access(path_map.c_str(), F_OK) == -1) continue;

		auto result = make_shared<ProcessInfo>(entry.path().filename().string());
		if(!result->running()) continue;

		auto process_path = result->path();
		if(process_path.empty()) continue;

		size_t namePos = process_path.find_last_of('/');
		if (namePos == -1) continue; // what?
		auto processName = process_path.substr(namePos + 1);

		cout << processName << endl;
		if (processName.compare(name) == 0)
			return result;
	}
	return nullptr;
}