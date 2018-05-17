#include "include/unique_loader.h"

using namespace std;
using namespace unique_instance;

#define MAX_PROCESS_SIZE 12

#ifdef WIN32
	#include <Windows.h>
	#include <iostream>
	#include <memory>

	#define PACK( __Declaration__ ) __pragma( pack(push, 1) ) __Declaration__ __pragma( pack(pop) )
#else
	#define PACK( __Declaration__ ) __Declaration__ __attribute__((__packed__))
#endif

PACK(
		struct ProcessEntry {
			DWORD process_id;
			int state;
		};
)

PACK(
		template <int N>
		struct Memory {
			HANDLE lock;
			ProcessEntry entries[N];
		};
)

PACK(
		struct MemoryHeader {
			int length;
		};
)

std::string cached_name;
std::shared_ptr<HANDLE> cached_entry;
inline std::shared_ptr<HANDLE> map_file(const std::string& name) {
	if(cached_name == name) return cached_entry;
	
	size_t size = sizeof(Memory<MAX_PROCESS_SIZE>) + sizeof(MemoryHeader);
	auto file =  CreateFileMapping(
			INVALID_HANDLE_VALUE,    // use paging file
			nullptr,                 // default security
			PAGE_READWRITE,          // read/write access
			(size >> 32) & 0xFFFFFFFFU, // maximum object size (high-order DWORD)
			(size >>  0) & 0xFFFFFFFFU, // maximum object size (low-order DWORD)
			name.c_str());                 // name of mapping object
	if(!file) {
		if(GetLastError() == ERROR_ALREADY_EXISTS) {
			//TODO map file!
		} else {
			cerr << "Could not map unique memory file! (" << GetLastError() << ")" << endl;
			return nullptr;
		}
	} else {
		auto header = (MemoryHeader*) file;
		header->length = MAX_PROCESS_SIZE;
		auto container = (Memory<MAX_PROCESS_SIZE>*) file + 1;
		ghMutex = CreateMutex(
				NULL,              // default security attributes
				FALSE,             // initially not owned
				NULL);             // unnamed mutex
		//Initialize file
	}
	//CreateFileMapping
}

bool unique_instance::self(const std::string &) {}
bool unique_instance::change_state(const std::string &, int state, bool require_own) {}
bool unique_instance::lock(const std::string &) {}
bool unique_instance::unlock(const std::string &, bool require_own) {}
bool unique_instance::change_state(const std::string &, int state, bool require_own) {}
int unique_instance::state(const std::string &) {}