#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>

#ifdef WIN32
	#include <Windows.h>
#endif
namespace mem {
	bool read(void* buffer, uintptr_t address, size_t length);
	bool write(void* data, uintptr_t address, size_t length);
	long pageSize();


	struct CodeFragment {
		uintptr_t address;

		void* old_fragment;
		void* new_fragment;
		size_t code_length;
		size_t fragment_length;

		inline uintptr_t jumpback_address() { return this->address + code_length; }

		~CodeFragment();
	};
	std::unique_ptr<CodeFragment> replace(uintptr_t address, void* new_code, size_t code_length, size_t fragment_length);
	bool rollback(const std::unique_ptr<CodeFragment>&);
}