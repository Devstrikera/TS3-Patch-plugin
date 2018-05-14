#include "include/wrapper/ParameterParser.h"
#include <iostream>
#include <cassert>
#ifdef WIN32
	#include "Windows.h"
#endif

using namespace std;
using namespace wrapper;

impl::ParameterParserFunctions* impl::fn_ParameterParser = nullptr;

int ParameterParser::getLastError() {
#ifdef WIN32
	#ifdef ENV32
		#error TODO HERE!
	#else
		return (int) *(DWORD*) (this + 64);
	#endif
#else
	return impl::fn_ParameterParser->getLastError(this);
#endif
}

#ifdef IMPLEMENT_DEPRECATED
int ParameterParser::getParamIndex(const TSString &key, int& index) {
	int local_index = 0; //If we use a ref it sometimes cause a sigfault.... unknown why :D
	auto result = impl::fn_ParameterParser->getParamIndex(this, key, local_index);
	index = local_index;
	return result;
}
#endif

int ParameterParser::getParamValueID(const TSString &key, ssize_t &index) {
	assert(impl::fn_ParameterParser->getParamValueID);
	return impl::fn_ParameterParser->getParamValueID(this, key, index);
}

struct TString {
	union {
		char data[0x10];
		struct {
			char* data_ptr;
			uintptr_t spacer;
		};
	} data;
	size_t length;
	size_t allocated;
	/*
	TString() : TString(0xF) {}
	TString(size_t length) {
		this->length = length;
		if(length > 0xF) {
			data.spacer = nullptr;
			data.data_ptr = nullptr;
		}
	}
	 */
	TString() {
		data.data_ptr = nullptr;
		data.spacer = 0;
		length = 0;
		allocated = 0xF;
	}

	inline ::string string() {
		return ::string(this->allocated > 0xF ? this->data.data_ptr : this->data.data, this->length);
	}
};

std::string ParameterParser::getParamValue(const TSString &key, ssize_t &index) {
	assert(impl::fn_ParameterParser->getParamValue);
#ifdef WIN32
	TString tmp;
	impl::fn_ParameterParser->getParamValue(this, &tmp, key, index);
	return tmp.string();
#else
	std::string response;
	impl::fn_ParameterParser->getParamValue(response, this, key, index);
	return response;
#endif
}

bool ParameterParser::hasParam(const TSString &key) {
	ssize_t index = 0;
	auto value = this->getParamValue(key, index);
	return this->getLastError() == 0;
	//return this->getParamIndex(key, index) > 0;
}