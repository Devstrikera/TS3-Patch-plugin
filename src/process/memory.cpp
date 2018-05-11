#include <cstring>
#include <include/process/process.h>
#include <sys/mman.h>
#include <iostream>

#include "include/process/memory.h"

using namespace std;
bool mem::read(void *buffer, uintptr_t address, size_t length) {
	memcpy(buffer, (void*) address, length);
	//FIXME test for validation?
	return true;
}

bool mem::write(void *data, uintptr_t address, size_t length) {
	uintptr_t pageAddress = address;

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

	memcpy((void*) address, data, length);
	return true;
}

long mem::pageSize() {
	return sysconf(_SC_PAGE_SIZE);
}

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
	memset(result->new_fragment + code_length, 0x90, fragment_length - code_length); //insert nop's
	if(!mem::write(result->new_fragment, address, fragment_length)) return nullptr;

	result->code_length = code_length;
	result->fragment_length = fragment_length;
	return result;
}

bool mem::rollback(const unique_ptr<CodeFragment>& fragment) {
	if(!fragment->old_fragment || !fragment->address) return false;

	return mem::write(fragment->old_fragment, fragment->address, fragment->fragment_length);
}