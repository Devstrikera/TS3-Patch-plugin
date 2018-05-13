#include <cstring>
#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#include "include/process/memory.h"

#ifndef WIN32
	#include <sys/mman.h>
#else

#endif

using namespace std;
bool mem::read(void *buffer, uintptr_t address, size_t length) {
	memcpy(buffer, (void*) address, length);
	//FIXME test for validation?
	return true;
}

bool mem::write(void *data, uintptr_t address, size_t length) {
	uintptr_t pageAddress = address;

#ifdef WIN32
	DWORD old;
	if(!VirtualProtect((PBYTE) address, length, PAGE_EXECUTE_READWRITE, &old)) {
		//TODO better error handling
		cerr << "Could not change address access! (" << pageAddress << ")" << endl;
	}
#else
	do {
		pageAddress -= pageAddress % pageSize();
		auto result = mprotect((void*) pageAddress, length, PROT_EXEC | PROT_READ | PROT_WRITE);
		if(result != 0) {
			//TODO better error handling
			cerr << "Could not change page access! (" << pageAddress << ")" << endl;
			return false;
		}
		pageAddress += pageSize();
	} while(pageAddress < address + length);
#endif

	memcpy((void*) address, data, length);
	return true;
}

#ifndef WIN32
	long mem::pageSize() {
		return sysconf(_SC_PAGE_SIZE);
	}
#endif

mem::CodeFragment::~CodeFragment()  {
	if(old_fragment) free(old_fragment);
	if(new_fragment) free(new_fragment);
}

unique_ptr<mem::CodeFragment> mem::replace(uintptr_t address, void *new_code, size_t code_length, size_t fragment_length) {
	unique_ptr<mem::CodeFragment> result;
	result.reset(new mem::CodeFragment{});

	result->address = address;
	result->old_fragment = malloc(fragment_length);
	result->new_fragment = malloc(fragment_length);
	if(!mem::read(result->old_fragment, address, fragment_length)) return nullptr;

	memcpy(result->new_fragment, new_code, code_length);
	memset(reinterpret_cast<unsigned char*>(result->new_fragment) + code_length, (int) 0x90, (size_t) fragment_length - code_length); //insert nop's
	cout << "Replacement: ";
	for(int i = 0; i < fragment_length; i++)
		cout << "0x" << hex << (uint32_t) (uint8_t) ((uint8_t*) result->new_fragment)[i] << " ";
	cout << endl << "Code: " << code_length << " Nop: " << fragment_length - code_length << endl;
	cout << "End addr: " << (void*) (address + fragment_length) << endl;
	if(!mem::write(result->new_fragment, address, fragment_length)) return nullptr;

	result->code_length = code_length;
	result->fragment_length = fragment_length;
	return result;
}

bool mem::rollback(const unique_ptr<CodeFragment>& fragment) {
	if(!fragment->old_fragment || !fragment->address) return false;

	return mem::write(fragment->old_fragment, fragment->address, fragment->fragment_length);
}