#include <malloc.h>
#include <cstring>
#include "include/wrapper/general.h"

using namespace wrapper;

TSString::TSString(const char *buffer) : TSString(buffer, strlen(buffer)) {}

TSString::TSString(const char *buffer, size_t length) : TSString(length) {
	memcpy(this->ptr, buffer, length);
}

TSString::TSString(size_t length) {
	this->ptr = (char *) malloc(length);
	this->length = length;
}

TSString::~TSString() {
	if (ptr) free(ptr);
}