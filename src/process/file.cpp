#include <iostream>
#include <zconf.h>
#include "../../include/process/file.h"

using namespace std;

std::string file::resolveSymbolicLink(const std::string& path) {
	char buffer[PATH_MAX];
	ssize_t len = ::readlink(path.c_str(), buffer, PATH_MAX);
	if(len < 0) len = 0;
	return string(buffer, len);

}